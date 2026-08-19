using System.Net;
using System.Text;
using ApricotFramework.Authentication;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// Input a provider, or a caller, should not be able to turn into something worse than a clean failure.
/// </summary>
public class AdversarialInputTests
{
    private const string Metadata = """
        {"issuer":"https://idp.example.com","token_endpoint":"https://idp.example.com/connect/token"}
        """;

    [Theory]
    [InlineData("orders&grant_type=password")]
    [InlineData("orders=read")]
    [InlineData("orders read")]
    [InlineData("orders+read")]
    [InlineData("orders%20read")]
    [InlineData("ordresé中文")]
    public async Task AuthenticateAsync_WithADelimiterInAScope_SendsItAsOneValueRatherThanAnotherField(string scope)
    {
        // Format injection: a scope carrying '&' or '=' would add fields to the request body if the body
        // were built by hand, and 'grant_type=password' is the field that matters.
        var handler = Provider();

        await Build(handler).AuthenticateAsync(
            new ClientAuthenticationParameters
            {
                Authority = "https://idp.example.com",
                ClientId = "svc",
                ClientSecret = "s3cret",
                Scopes = [scope],
            },
            TestContext.Current.CancellationToken);

        var request = handler.LastFor("/connect/token");

        Assert.Equal(scope, request.Field("scope"));
        Assert.Equal(["client_credentials"], request.Fields("grant_type"));
    }

    [Theory]
    [InlineData("urn:orders&resource=urn:everything")]
    [InlineData("urn:orders=1")]
    public async Task AuthenticateAsync_WithADelimiterInAResource_SendsItAsOneValue(string resource)
    {
        var handler = Provider();

        await Build(handler).AuthenticateAsync(
            new ClientAuthenticationParameters
            {
                Authority = "https://idp.example.com",
                ClientId = "svc",
                ClientSecret = "s3cret",
                Resources = [resource],
            },
            TestContext.Current.CancellationToken);

        Assert.Equal([resource], handler.LastFor("/connect/token").Fields("resource"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithAVeryLongScopeList_StillSendsOneRequest()
    {
        var handler = Provider();
        var scopes = Enumerable.Range(0, 5_000).Select(index => $"scope-{index}").ToArray();

        await Build(handler).AuthenticateAsync(
            new ClientAuthenticationParameters
            {
                Authority = "https://idp.example.com",
                ClientId = "svc",
                ClientSecret = "s3cret",
                Scopes = scopes,
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(1, handler.CountFor("/connect/token"));
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("\"a string\"")]
    [InlineData("42")]
    [InlineData("null")]
    public async Task AuthenticateAsync_WhenTheMetadataIsNotAnObject_FailsCleanly(string body)
    {
        var handler = new StubHttpMessageHandler().On(".well-known", HttpStatusCode.OK, body);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.NotEqual(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Theory]
    [InlineData("""{"access_token":"at-1","expires_in":"not a number"}""")]
    [InlineData("""{"access_token":"at-1","expires_in":true}""")]
    [InlineData("""{"access_token":"at-1","expires_in":{}}""")]
    public async Task AuthenticateAsync_WithAnUnreadableLifetime_FailsCleanly(string body)
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, body);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unknown, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAVeryLongAccessToken_ReturnsItWhole()
    {
        var token = new string('t', 200_000);
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, $$"""{"access_token":"{{token}}","expires_in":3600}""");

        var context = await Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal(token.Length, context.Token.Length);
    }

    [Theory]
    [InlineData("https://idp.example.com")]
    [InlineData("https://idp.example.com/")]
    public async Task AuthenticateAsync_WithOrWithoutATrailingSlash_ReadsTheSameMetadataUrl(string authority)
    {
        var handler = Provider();

        await Build(handler).AuthenticateAsync(
            Parameters(authority),
            TestContext.Current.CancellationToken);

        Assert.Equal(
            "https://idp.example.com/.well-known/openid-configuration",
            handler.LastFor(".well-known").Uri.AbsoluteUri);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheMetadataIsHuge_FailsWithoutReadingItAll()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", new StringContent(new string('x', 4 * 1024 * 1024), Encoding.UTF8, "application/json"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAnEmptySecret_StillSendsAWellFormedHeader()
    {
        // A missing secret is a configuration mistake, but it has to reach the provider as an empty
        // password rather than as a malformed header the provider cannot parse at all.
        var handler = Provider();

        await Build(handler).AuthenticateAsync(
            new ClientAuthenticationParameters
            {
                Authority = "https://idp.example.com",
                ClientId = "svc",
                ClientSecret = null,
            },
            TestContext.Current.CancellationToken);

        var parameter = handler.LastFor("/connect/token").AuthorizationParameter;

        Assert.Equal("svc:", Encoding.UTF8.GetString(Convert.FromBase64String(parameter!)));
    }

    private static StubHttpMessageHandler Provider()
    {
        return new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, """{"access_token":"at-1","expires_in":3600}""");
    }

    private static ClientCredentialsAuthenticator Build(StubHttpMessageHandler handler)
    {
        return new ClientCredentialsAuthenticator(handler.CreateClient(), new TestTokenCache());
    }

    private static ClientAuthenticationParameters Parameters(string authority = "https://idp.example.com")
    {
        return new ClientAuthenticationParameters
        {
            Authority = authority,
            ClientId = "svc",
            ClientSecret = "s3cret",
        };
    }
}
