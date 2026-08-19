using ApricotFramework.Authentication.AspNetCore;
using ApricotFramework.Authentication.AspNetCore.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class ConfigAwareClientAuthenticatorTests
{
    [Fact]
    public async Task AuthenticateAsync_WithNoParameters_UsesTheConfiguredClient()
    {
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings());

        var context = await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("at-1", context.Token);

        // Basic of "svc:s3cret", so the configured credentials reached the request.
        Assert.Equal(
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("svc:s3cret")),
            handler.TokenRequest.Authorization);
    }

    [Fact]
    public async Task AuthenticateAsync_PrefersTheClientAuthorityOverTheInboundOne()
    {
        // A service may accept tokens from one issuer and call services that trust another.
        var handler = new RecordingHandler("https://tokens.example.com");
        var settings = Settings();
        settings["Authentication:Client:Authority"] = "https://tokens.example.com";

        using var provider = Build(handler, settings);

        await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.StartsWith("https://tokens.example.com", handler.TokenRequest.Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_WithoutAClientAuthority_FallsBackToTheInboundOne()
    {
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings());

        await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.StartsWith("https://idp.example.com", handler.TokenRequest.Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_WithNoParameters_UsesTheConfiguredScopesAndResources()
    {
        var handler = new RecordingHandler("https://idp.example.com");
        var settings = Settings();
        settings["Authentication:Client:Scopes:0"] = "orders.read";
        settings["Authentication:Client:Scopes:1"] = "orders.write";
        settings["Authentication:Client:Resources:0"] = "urn:orders";

        using var provider = Build(handler, settings);

        await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("orders.read orders.write", handler.Field("scope"));
        Assert.Equal(["urn:orders"], handler.Fields("resource"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheCallerNamesScopes_UsesThoseRatherThanTheConfigured()
    {
        var handler = new RecordingHandler("https://idp.example.com");
        var settings = Settings();
        settings["Authentication:Client:Scopes:0"] = "orders.read";

        using var provider = Build(handler, settings);

        await provider.GetRequiredService<IClientAuthenticator>().AuthenticateAsync(
            new ClientAuthenticationParameters { Scopes = ["billing.read"] },
            TestContext.Current.CancellationToken);

        Assert.Equal("billing.read", handler.Field("scope"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheCallerNamesAnEmptyScopeList_RequestsNoScopes()
    {
        // An empty list from a caller means "no scopes", not "fall back to the configured ones".
        var handler = new RecordingHandler("https://idp.example.com");
        var settings = Settings();
        settings["Authentication:Client:Scopes:0"] = "orders.read";

        using var provider = Build(handler, settings);

        await provider.GetRequiredService<IClientAuthenticator>().AuthenticateAsync(
            new ClientAuthenticationParameters { Scopes = [] },
            TestContext.Current.CancellationToken);

        Assert.Null(handler.Field("scope"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithPostBodyStyleConfigured_SendsCredentialsInTheBody()
    {
        var handler = new RecordingHandler("https://idp.example.com");
        var settings = Settings();
        settings["Authentication:Client:CredentialStyle"] = "PostBody";

        using var provider = Build(handler, settings);

        await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Null(handler.TokenRequest.Authorization);
        Assert.Equal("svc", handler.Field("client_id"));
        Assert.Equal("s3cret", handler.Field("client_secret"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithAnHttpAuthorityAndAllowInsecure_Succeeds()
    {
        // The development case: the scheme check has to be relaxed as well as certificate validation,
        // which the predecessor did not do.
        var handler = new RecordingHandler("http://localhost:5001");
        var settings = Settings(authority: "http://localhost:5001");
        settings["Authentication:AllowInsecure"] = "true";

        using var provider = Build(handler, settings);

        var context = await provider.GetRequiredService<IClientAuthenticator>()
            .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("at-1", context.Token);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAnHttpAuthorityAndWithoutAllowInsecure_NeverReachesTheProvider()
    {
        // Caught by the settings check rather than by the request, so the secret is never put on the
        // wire at all. The authenticator refuses it too, for a host that builds one by hand.
        var handler = new RecordingHandler("http://localhost:5001");
        var settings = Settings();
        settings["Authentication:Client:Authority"] = "http://localhost:5001";

        using var provider = Build(handler, settings);

        await Assert.ThrowsAsync<Microsoft.Extensions.Options.OptionsValidationException>(
            () => provider.GetRequiredService<IClientAuthenticator>()
                .AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task AuthenticateAsync_TwiceForTheSameParameters_ReadsTheMetadataOnceAndCachesTheToken()
    {
        var handler = new RecordingHandler("https://idp.example.com");

        using var provider = Build(handler, Settings());
        var authenticator = provider.GetRequiredService<IClientAuthenticator>();

        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);
        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(1, handler.Requests.Count(request => request.Uri.AbsoluteUri.Contains(".well-known", StringComparison.Ordinal)));
        Assert.Equal(1, handler.Requests.Count(request => request.Uri.AbsoluteUri.Contains("/connect/token", StringComparison.Ordinal)));
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

    private static ServiceProvider Build(RecordingHandler handler, Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();

        services.AddClientAuthentication(configuration);

        // Registered afterwards, so it replaces the handler the library configured.
        services.AddHttpClient(AuthenticationHttpClients.Token).ConfigurePrimaryHttpMessageHandler(() => handler);

        return services.BuildServiceProvider(validateScopes: true);
    }
}
