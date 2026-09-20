using System.Net;
using ApricotFramework.Authentication.Caching;
using ApricotFramework.Authentication.Hosting;
using ApricotFramework.Authentication.TokenExchange;

namespace ApricotFramework.Authentication.Tests;

public class TokenExchangeAuthenticatorTests
{
    private const string Metadata = """
        {"issuer":"https://idp.example.com","token_endpoint":"https://idp.example.com/connect/token"}
        """;

    [Fact]
    public async Task AuthenticateAsync_SendsTheExchangeGrantAndTheSubjectToken()
    {
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject("alice-token"));

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        var body = handler.LastFor("/connect/token").Body;

        Assert.Contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", body, StringComparison.Ordinal);
        Assert.Contains("subject_token=alice-token", body, StringComparison.Ordinal);
        Assert.Contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_StillAuthenticatesTheClientItself()
    {
        // RFC 8693 keeps client authentication: the exchange says who is being acted for, not who
        // is asking.
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject("alice-token"));

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal("Basic", handler.LastFor("/connect/token").AuthorizationScheme);
    }

    [Fact]
    public async Task AuthenticateAsync_SendsScopeAndResourceAsAnyGrantWould()
    {
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject("alice-token"));

        await authenticator.AuthenticateAsync(
            Parameters(scopes: ["api.agent"], resources: ["urn:svc:api"]),
            TestContext.Current.CancellationToken);

        var body = handler.LastFor("/connect/token").Body;

        Assert.Contains("scope=api.agent", body, StringComparison.Ordinal);
        Assert.Contains("resource=urn%3Asvc%3Aapi", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_WithNoSubject_FailsRatherThanActingAsTheServiceItself()
    {
        // The substitution this design exists to prevent: no subject must never quietly become a
        // token carrying the service's own authority.
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject(null));

        var failure = await Assert.ThrowsAsync<TokenRequestException>(
            () => authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(TokenRequestFailure.InvalidCredentials, failure.Reason);
        Assert.Equal(0, handler.CountFor("/connect/token"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheCallerSuppliedASubject_DoesNotConsultTheProvider()
    {
        var handler = Provider();
        var provider = Subject("from-provider");
        var authenticator = Build(handler, new TestTokenCache(), provider);

        var parameters = Parameters();
        parameters.SubjectToken = "from-caller";

        await authenticator.AuthenticateAsync(parameters, TestContext.Current.CancellationToken);

        Assert.Equal(0, provider.Calls);
        Assert.Contains("subject_token=from-caller", handler.LastFor("/connect/token").Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_DoesNotMutateTheCallersParameters()
    {
        // The caller may reuse the object for the next call, and a subject written into it would
        // then be sent on behalf of whoever came first.
        var authenticator = Build(Provider(), new TestTokenCache(), Subject("alice-token"));

        var parameters = Parameters();
        await authenticator.AuthenticateAsync(parameters, TestContext.Current.CancellationToken);

        Assert.Null(parameters.SubjectToken);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAnActorToken_SendsItsTypeAsWell()
    {
        // Required whenever an actor token is present, per RFC 8693 section 2.1.
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject("alice-token"));

        var parameters = Parameters();
        parameters.ActorToken = "actor-token";

        await authenticator.AuthenticateAsync(parameters, TestContext.Current.CancellationToken);

        var body = handler.LastFor("/connect/token").Body;

        Assert.Contains("actor_token=actor-token", body, StringComparison.Ordinal);
        Assert.Contains("actor_token_type=", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAudiences_SendsOneParameterEach()
    {
        var handler = Provider();
        var authenticator = Build(handler, new TestTokenCache(), Subject("alice-token"));

        var parameters = Parameters();
        parameters.Audiences = ["one", "two"];

        await authenticator.AuthenticateAsync(parameters, TestContext.Current.CancellationToken);

        var body = handler.LastFor("/connect/token").Body;

        Assert.Contains("audience=one", body, StringComparison.Ordinal);
        Assert.Contains("audience=two", body, StringComparison.Ordinal);
    }

    private static StubHttpMessageHandler Provider(string token = """{"access_token":"at-1","expires_in":3600}""")
    {
        return new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, token);
    }

    private static TokenExchangeAuthenticator Build(
        StubHttpMessageHandler handler,
        ITokenCache cache,
        TestSubjectTokenProvider subjectTokenProvider)
    {
        return new TokenExchangeAuthenticator(
            cache,
            new StaticTokenRequestHostingContext(handler.CreateClient()),
            subjectTokenProvider);
    }

    private static TestSubjectTokenProvider Subject(string? value)
    {
        return new TestSubjectTokenProvider(value);
    }

    private static TokenRequestParameters Parameters(
        IReadOnlyList<string>? scopes = null,
        IReadOnlyList<string>? resources = null)
    {
        return new TokenRequestParameters
        {
            Authority = "https://idp.example.com",
            ClientId = "svc",
            ClientSecret = "s3cret",
            Scopes = scopes,
            Resources = resources,
        };
    }
}
