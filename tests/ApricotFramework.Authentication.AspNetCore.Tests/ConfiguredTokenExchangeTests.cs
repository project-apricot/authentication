using System.Security.Claims;
using ApricotFramework.Authentication.AspNetCore.Extensions;
using ApricotFramework.Authentication.ClientCredentials;
using ApricotFramework.Authentication.TokenExchange;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class ConfiguredTokenExchangeTests
{
    [Fact]
    public async Task AuthenticateAsync_ExchangesTheTokenTheRequestArrivedWith()
    {
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings(), Authenticated("inbound-token", "alice"));

        var context = await provider.GetRequiredService<ITokenExchangeAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("at-1", context.Value);
        Assert.Equal(TokenExchangeAuthenticator.TokenExchangeGrantType, handler.Field("grant_type"));
        Assert.Equal("inbound-token", handler.Field("subject_token"));
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, handler.Field("subject_token_type"));
    }

    [Fact]
    public async Task AuthenticateAsync_StillAuthenticatesAsTheConfiguredClient()
    {
        // RFC 8693 does not change who the client is, only whose authority the result carries.
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings(), Authenticated("inbound-token", "alice"));

        await provider.GetRequiredService<ITokenExchangeAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("svc:s3cret")),
            handler.TokenRequest.Authorization);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAPerCallResource_KeepsTheSubjectTheRequestSupplied()
    {
        // The configured defaults are filled in around the subject the grant already resolved, not
        // over a fresh parameter set that would have dropped it.
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings(), Authenticated("inbound-token", "alice"));

        await provider.GetRequiredService<ITokenExchangeAuthenticator>().AuthenticateAsync(
            new TokenRequestParameters { Resources = ["urn:svc:content"], Scopes = ["content.agent"] },
            TestContext.Current.CancellationToken);

        Assert.Equal("inbound-token", handler.Field("subject_token"));
        Assert.Equal(["urn:svc:content"], handler.Fields("resource"));
        Assert.Equal("content.agent", handler.Field("scope"));
    }

    [Fact]
    public async Task AuthenticateAsync_OnAnAnonymousRequest_RefusesRatherThanActingAsItself()
    {
        // The failure that matters: falling back to client credentials here would hand the caller
        // this service's authority on exactly the calls where they could not be identified.
        var handler = new RecordingHandler("https://idp.example.com");
        var anonymous = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity()) };

        using var provider = Build(handler, Settings(), anonymous);

        var failure = await Assert.ThrowsAsync<TokenRequestException>(
            () => provider.GetRequiredService<ITokenExchangeAuthenticator>()
                .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(TokenRequestFailure.InvalidCredentials, failure.Reason);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task AuthenticateAsync_ForTwoDifferentCallers_DoesNotServeOneTheOthersToken()
    {
        // One container, one cache, two people. The subject is part of the key, so the second call
        // is a miss.
        var handler = new RecordingHandler("https://idp.example.com");
        var accessor = new HttpContextAccessor { HttpContext = Authenticated("alice-token", "alice") };

        using var provider = Build(handler, Settings(), accessor);
        var authenticator = provider.GetRequiredService<ITokenExchangeAuthenticator>();

        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        accessor.HttpContext = Authenticated("bob-token", "bob");

        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        var exchanges = handler.Requests
            .Where(request => request.Uri.AbsoluteUri.Contains("/connect/token", StringComparison.Ordinal))
            .ToList();

        Assert.Equal(2, exchanges.Count);
        Assert.Contains("alice-token", exchanges[0].Body, StringComparison.Ordinal);
        Assert.Contains("bob-token", exchanges[1].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_TwiceForOneCaller_ExchangesOnceAndServesTheCachedToken()
    {
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings(), Authenticated("inbound-token", "alice"));
        var authenticator = provider.GetRequiredService<ITokenExchangeAuthenticator>();

        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);
        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(1, handler.Requests.Count(request => request.Uri.AbsoluteUri.Contains("/connect/token", StringComparison.Ordinal)));
    }

    [Fact]
    public void AddTokenExchangeAuthentication_LeavesTheClientCredentialsAuthenticatorAlone()
    {
        // Parallel registrations, not ranked. Adding the exchange must not change how a call that
        // authenticates as this service behaves.
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(Settings()).Build();
        var services = new ServiceCollection();

        services.AddTokenExchangeAuthentication(configuration);

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.IsType<ClientCredentialsAuthenticator>(provider.GetRequiredService<IClientCredentialsAuthenticator>());
        Assert.IsType<TokenExchangeAuthenticator>(provider.GetRequiredService<ITokenExchangeAuthenticator>());
    }

    [Fact]
    public void AddTokenExchangeAuthentication_LeavesASubjectProviderAHostRegisteredFirstAlone()
    {
        // The subject need not come from an inbound request: a queue worker acting on a stored
        // delegation supplies its own and keeps everything else.
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(Settings()).Build();
        var services = new ServiceCollection();

        services.AddSingleton<ISubjectTokenProvider, FixedSubjectTokenProvider>();
        services.AddTokenExchangeAuthentication(configuration);

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.IsType<FixedSubjectTokenProvider>(provider.GetRequiredService<ISubjectTokenProvider>());
    }

    private static DefaultHttpContext Authenticated(string token, string subject)
    {
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "Bearer")),
        };

        context.Request.Headers.Authorization = $"Bearer {token}";

        return context;
    }

    private static Dictionary<string, string?> Settings(string authority = "https://idp.example.com")
    {
        return new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Authentication:Authority"] = authority,
            ["Authentication:ValidAudiences:0"] = "api",
            ["Authentication:Client:ClientId"] = "svc",
            ["Authentication:Client:ClientSecret"] = "s3cret",
        };
    }

    private static ServiceProvider Build(RecordingHandler handler, Dictionary<string, string?> settings, HttpContext httpContext)
    {
        return Build(handler, settings, new HttpContextAccessor { HttpContext = httpContext });
    }

    private static ServiceProvider Build(RecordingHandler handler, Dictionary<string, string?> settings, IHttpContextAccessor accessor)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();

        services.AddTokenExchangeAuthentication(configuration);

        // Registered afterwards, so they replace what the library configured conditionally.
        services.AddSingleton(accessor);
        services.AddHttpClient(AuthenticationHttpClients.Token).ConfigurePrimaryHttpMessageHandler(() => handler);

        return services.BuildServiceProvider(validateScopes: true);
    }

    private sealed class FixedSubjectTokenProvider : ISubjectTokenProvider
    {
        public ValueTask<SubjectToken?> GetSubjectTokenAsync(CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<SubjectToken?>(new SubjectToken("stored"));
        }
    }
}
