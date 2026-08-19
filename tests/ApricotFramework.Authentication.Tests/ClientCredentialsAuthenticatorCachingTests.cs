using System.Net;
using ApricotFramework.Authentication;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.Tests;

public class ClientCredentialsAuthenticatorCachingTests
{
    private const string Metadata = """
        {"issuer":"https://idp.example.com","token_endpoint":"https://idp.example.com/connect/token"}
        """;

    [Fact]
    public async Task AuthenticateAsync_CalledTwice_ReadsTheMetadataOnce()
    {
        var handler = Provider();
        var cache = new TestTokenCache();
        var authenticator = Build(handler, cache);

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);
        await authenticator.AuthenticateAsync(Parameters(scopes: ["other"]), TestContext.Current.CancellationToken);

        Assert.Equal(1, handler.CountFor(".well-known"));
        Assert.Equal(2, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenATokenIsCached_DoesNotRequestAnother()
    {
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache());

        var first = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);
        var second = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal(first.Token, second.Token);
        Assert.Equal(1, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithDifferentScopes_RequestsASeparateToken()
    {
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache());

        await authenticator.AuthenticateAsync(Parameters(scopes: ["read"]), TestContext.Current.CancellationToken);
        await authenticator.AuthenticateAsync(Parameters(scopes: ["write"]), TestContext.Current.CancellationToken);

        Assert.Equal(2, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_CachesTheTokenForLessThanItsLifetime()
    {
        // The skew is what keeps a token from expiring between being handed out and being used.
        var cache = new TestTokenCache();
        var authenticator = Build(Provider(), cache);

        var before = DateTimeOffset.UtcNow;
        var context = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        var cachedUntil = cache.ExpiryOf(Parameters());

        Assert.NotNull(cachedUntil);
        Assert.True(cachedUntil < context.ExpiresAt, "the entry must expire before the token does");
        Assert.InRange(
            cachedUntil.Value,
            before.AddSeconds(3600 - 30 - 5),
            before.AddSeconds(3600 - 30 + 5));
    }

    [Fact]
    public async Task AuthenticateAsync_WithExpiresInAsAString_ReadsTheLifetime()
    {
        // Providers exist that quote it, and refusing those would be a parse failure rather than
        // the interoperability the specification intends.
        var cache = new TestTokenCache();
        var authenticator = Build(
            Provider("""{"access_token":"at-1","expires_in":"600"}"""),
            cache);

        var context = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.NotNull(context.ExpiresAt);
        Assert.NotNull(cache.ExpiryOf(Parameters()));
    }

    [Fact]
    public async Task AuthenticateAsync_WithAnAbsurdExpiresIn_CapsTheLifetimeRatherThanOverflowing()
    {
        var cache = new TestTokenCache();
        var authenticator = Build(
            Provider("""{"access_token":"at-1","expires_in":99999999999999}"""),
            cache);

        var before = DateTimeOffset.UtcNow;
        var context = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.NotNull(context.ExpiresAt);
        Assert.InRange(context.ExpiresAt.Value, before.AddHours(23), before.AddHours(25));
    }

    [Theory]
    [InlineData("""{"access_token":"at-1"}""")]
    [InlineData("""{"access_token":"at-1","expires_in":0}""")]
    [InlineData("""{"access_token":"at-1","expires_in":-60}""")]
    [InlineData("""{"access_token":"at-1","expires_in":10}""")]
    public async Task AuthenticateAsync_WhenTheLifetimeIsAbsentOrInsideTheSkew_DoesNotCache(string body)
    {
        // Caching a token whose remaining life is shorter than the skew would serve one about to
        // expire; guessing a lifetime when none was stated would serve one already expired.
        var handler = Provider(body);
        var cache = new TestTokenCache();
        var authenticator = Build(handler, cache);

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);
        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal(0, cache.TokenWrites);
        Assert.Equal(2, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithoutATokenType_ReportsBearer()
    {
        var authenticator = Build(Provider("""{"access_token":"at-1","expires_in":3600}"""), new TestTokenCache());

        var context = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal("Bearer", context.TokenType);
    }

    [Fact]
    public async Task AuthenticateAsync_WithATokenType_ReportsItExactlyAsGiven()
    {
        var authenticator = Build(
            Provider("""{"access_token":"at-1","token_type":"DPoP","expires_in":3600}"""),
            new TestTokenCache());

        var context = await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal("DPoP", context.TokenType);
    }

    [Fact]
    public async Task AuthenticateAsync_WithManyConcurrentCallers_RequestsOneToken()
    {
        // Without coalescing every request on a cold cache hits the provider, which is exactly when a
        // service is least able to absorb the extra round trips.
        var release = new TaskCompletionSource();
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", async (_, _) =>
            {
                await release.Task;

                return Json("""{"access_token":"at-1","expires_in":3600}""");
            });

        var authenticator = Build(handler, new TestTokenCache());

        var callers = Enumerable
            .Range(0, 20)
            .Select(_ => authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken))
            .ToArray();

        release.SetResult();

        var contexts = await Task.WhenAll(callers);

        Assert.All(contexts, context => Assert.Equal("at-1", context.Token));
        Assert.Equal(1, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenOneCallerCancels_StillAnswersTheOthers()
    {
        // The reason the shared request does not carry any one caller's token: one caller walking away
        // must not fail the request the rest are waiting on.
        var release = new TaskCompletionSource();
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", async (_, _) =>
            {
                await release.Task;

                return Json("""{"access_token":"at-1","expires_in":3600}""");
            });

        var authenticator = Build(handler, new TestTokenCache());

        using var cancellation = new CancellationTokenSource();

        var abandoning = authenticator.AuthenticateAsync(Parameters(), cancellation.Token);
        var waiting = authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoning);

        release.SetResult();

        Assert.Equal("at-1", (await waiting).Token);
        Assert.Equal(1, handler.CountFor("/connect/token"));
    }

    private static HttpResponseMessage Json(string body)
    {
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        };
    }

    private static StubHttpMessageHandler Provider(string token = """{"access_token":"at-1","expires_in":3600}""")
    {
        return new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, token);
    }

    private static ClientCredentialsAuthenticator Build(StubHttpMessageHandler handler, IClientAuthenticationCache cache)
    {
        return new ClientCredentialsAuthenticator(handler.CreateClient(), cache);
    }

    private static ClientAuthenticationParameters Parameters(IReadOnlyList<string>? scopes = null)
    {
        return new ClientAuthenticationParameters
        {
            Authority = "https://idp.example.com",
            ClientId = "svc",
            ClientSecret = "s3cret",
            Scopes = scopes,
        };
    }
}
