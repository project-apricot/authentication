using System.Net;
using System.Text;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.Tests;

public class ClientCredentialsAuthenticatorTests
{
    private const string Authority = "https://idp.example.com";

    private const string Metadata = """
        {"issuer":"https://idp.example.com","token_endpoint":"https://idp.example.com/connect/token"}
        """;

    private const string IssuedToken = """
        {"access_token":"at-1","token_type":"Bearer","expires_in":3600}
        """;

    [Fact]
    public async Task AuthenticateAsync_WithBasicStyle_EncodesCredentialsAsTheSpecificationDoes()
    {
        // The worked example from RFC 6749 section 2.3.1, whose expected value the RFC itself prints.
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(clientId: "s6BhdRkqt3", clientSecret: "gX1fBat3bV"), TestContext.Current.CancellationToken);

        var request = handler.LastFor("/connect/token");

        Assert.Equal("Basic", request.AuthorizationScheme);
        Assert.Equal("czZCaGRSa3F0MzpnWDFmQmF0M2JW", request.AuthorizationParameter);
    }

    [Theory]
    // Both expected values computed with Python's base64 and urllib.parse.quote_plus, not with this code.
    [InlineData("a b", "p:w+d", "YStiOnAlM0F3JTJCZA==")]
    [InlineData("sérvice", "sëcret", "cyVDMyVBOXJ2aWNlOnMlQzMlQUJjcmV0")]
    public async Task AuthenticateAsync_WithCredentialsNeedingEscaping_EncodesEachHalfBeforeJoining(
        string clientId,
        string clientSecret,
        string expected)
    {
        // Without the form encoding, a secret containing a colon splits in the wrong place and the
        // provider reads a different secret than was configured.
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(clientId: clientId, clientSecret: clientSecret), TestContext.Current.CancellationToken);

        Assert.Equal(expected, handler.LastFor("/connect/token").AuthorizationParameter);
    }

    [Fact]
    public async Task AuthenticateAsync_WithBasicStyle_KeepsCredentialsOutOfTheBody()
    {
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        var request = handler.LastFor("/connect/token");

        Assert.Equal("client_credentials", request.Field("grant_type"));
        Assert.Null(request.Field("client_id"));
        Assert.Null(request.Field("client_secret"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithPostBodyStyle_SendsCredentialsInTheBodyAndNoHeader()
    {
        var handler = Provider();
        var authenticator = Build(
            handler,
            new ClientCredentialsAuthenticatorOptions { CredentialStyle = ClientCredentialStyle.PostBody });

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        var request = handler.LastFor("/connect/token");

        Assert.Null(request.AuthorizationScheme);
        Assert.Equal("svc", request.Field("client_id"));
        Assert.Equal("s3cret", request.Field("client_secret"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithScopes_JoinsThemWithSpaces()
    {
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(scopes: ["orders.read", "orders.write"]), TestContext.Current.CancellationToken);

        Assert.Equal("orders.read orders.write", handler.LastFor("/connect/token").Field("scope"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithNoScopes_OmitsTheScopeField()
    {
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Null(handler.LastFor("/connect/token").Field("scope"));
    }

    [Fact]
    public async Task AuthenticateAsync_WithResources_SendsOneParameterEach()
    {
        // RFC 8707 repeats the parameter rather than joining, and a joined list is silently read as
        // one long resource identifier.
        var handler = Provider();
        var authenticator = Build(handler);

        await authenticator.AuthenticateAsync(Parameters(resources: ["urn:orders", "urn:billing"]), TestContext.Current.CancellationToken);

        Assert.Equal(["urn:orders", "urn:billing"], handler.LastFor("/connect/token").Fields("resource"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataNamesAnotherIssuer_FailsAsInvalidConfiguration()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"https://evil.example.com","token_endpoint":"https://idp.example.com/connect/token"}
                """);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataNamesAnEndpointElsewhere_FailsAsInvalidConfiguration()
    {
        // The attack the origin check exists for: a substituted document that collects the secret.
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"https://idp.example.com","token_endpoint":"https://evil.example.com/token"}
                """);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
        Assert.Equal(0, handler.CountFor("evil.example.com"));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataNamesAnEndpointOnAnotherPort_FailsAsInvalidConfiguration()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"https://idp.example.com","token_endpoint":"https://idp.example.com:8443/token"}
                """);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataHasNoTokenEndpoint_FailsAsInvalidConfiguration()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """{"issuer":"https://idp.example.com"}""");

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataIssuerDiffersOnlyByTrailingSlash_Succeeds()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"https://idp.example.com/","token_endpoint":"https://idp.example.com/connect/token"}
                """)
            .On("/connect/token", HttpStatusCode.OK, IssuedToken);

        var context = await Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken);

        Assert.Equal("at-1", context.Token);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenMetadataIsUnreachable_FailsAsUnavailable()
    {
        var handler = new StubHttpMessageHandler()
            .OnThrow(".well-known", new HttpRequestException("no route to host"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_ReadsMetadataFromTheAuthorityPath()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"https://idp.example.com/tenant-a","token_endpoint":"https://idp.example.com/tenant-a/token"}
                """)
            .On("/tenant-a/token", HttpStatusCode.OK, IssuedToken);

        await Build(handler).AuthenticateAsync(Parameters(authority: "https://idp.example.com/tenant-a"), TestContext.Current.CancellationToken);

        Assert.Equal(
            "https://idp.example.com/tenant-a/.well-known/openid-configuration",
            handler.LastFor(".well-known").Uri.AbsoluteUri);
    }

    [Fact]
    public async Task AuthenticateAsync_WithHttpAuthority_FailsAsInvalidConfiguration()
    {
        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(Provider()).AuthenticateAsync(Parameters(authority: "http://idp.example.com"), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WithHttpAuthorityWhenInsecureIsAllowed_Succeeds()
    {
        // The development case the setting exists for. It failed before, because relaxing certificate
        // validation alone left the scheme check in place.
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, """
                {"issuer":"http://idp.example.com","token_endpoint":"http://idp.example.com/connect/token"}
                """)
            .On("/connect/token", HttpStatusCode.OK, IssuedToken);

        var authenticator = Build(
            handler,
            new ClientCredentialsAuthenticatorOptions { AllowInsecureAuthority = true });

        var context = await authenticator.AuthenticateAsync(Parameters(authority: "http://idp.example.com"), TestContext.Current.CancellationToken);

        Assert.Equal("at-1", context.Token);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("idp.example.com")]
    [InlineData("/connect/token")]
    [InlineData("ftp://idp.example.com")]
    public async Task AuthenticateAsync_WithAnUnusableAuthority_FailsAsInvalidConfiguration(string? authority)
    {
        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(Provider()).AuthenticateAsync(Parameters(authority: authority), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WithoutAClientId_FailsAsInvalidConfiguration()
    {
        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(Provider()).AuthenticateAsync(Parameters(clientId: null), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidConfiguration, failure.Reason);
    }

    [Theory]
    [InlineData("invalid_client", ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData("unauthorized_client", ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData("invalid_grant", ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData("invalid_scope", ClientAuthenticationFailure.InvalidScope)]
    [InlineData("invalid_request", ClientAuthenticationFailure.InvalidConfiguration)]
    [InlineData("unsupported_grant_type", ClientAuthenticationFailure.InvalidConfiguration)]
    [InlineData("server_error", ClientAuthenticationFailure.Unavailable)]
    [InlineData("temporarily_unavailable", ClientAuthenticationFailure.Unavailable)]
    [InlineData("INVALID_CLIENT", ClientAuthenticationFailure.Unknown)]
    [InlineData("something_new", ClientAuthenticationFailure.Unknown)]
    public async Task AuthenticateAsync_WithAProviderError_ReportsTheMatchingFailure(
        string error,
        ClientAuthenticationFailure expected)
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.BadRequest, $$"""{"error":"{{error}}"}""");

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(expected, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheErrorDescriptionEchoesTheRequest_KeepsItOutOfTheMessage()
    {
        // Providers echo the request into error_description, and a request to a token endpoint
        // carries a secret.
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.BadRequest, """
                {"error":"invalid_client","error_description":"client_secret=s3cret was rejected"}
                """);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.DoesNotContain("s3cret", failure.Message, StringComparison.Ordinal);
        Assert.Contains("invalid_client", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData(HttpStatusCode.Forbidden, ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData(HttpStatusCode.InternalServerError, ClientAuthenticationFailure.Unavailable)]
    [InlineData(HttpStatusCode.BadGateway, ClientAuthenticationFailure.Unavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, ClientAuthenticationFailure.Unavailable)]
    [InlineData(HttpStatusCode.TooManyRequests, ClientAuthenticationFailure.Unavailable)]
    [InlineData(HttpStatusCode.RequestTimeout, ClientAuthenticationFailure.Unavailable)]
    [InlineData(HttpStatusCode.BadRequest, ClientAuthenticationFailure.Unknown)]
    public async Task AuthenticateAsync_WithAnEmptyErrorResponse_ClassifiesByStatusCode(
        HttpStatusCode status,
        ClientAuthenticationFailure expected)
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", status);

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(expected, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheResponseCarriesNoToken_FailsAsUnknown()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, """{"token_type":"Bearer","expires_in":3600}""");

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unknown, failure.Reason);
    }

    [Theory]
    [InlineData("<html><body>Gateway error</body></html>")]
    [InlineData("")]
    [InlineData("{\"access_token\":")]
    public async Task AuthenticateAsync_WhenTheResponseIsNotJson_FailsWithoutThrowingSomethingElse(string body)
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", new StringContent(body, Encoding.UTF8, "text/html"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unknown, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheResponseExceedsTheCap_FailsAsUnavailable()
    {
        // A provider that has broken, or been substituted, cannot be answered with the process memory.
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", new StringContent(new string('x', 2 * 1024 * 1024), Encoding.UTF8, "application/json"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheTransportFails_FailsAsUnavailable()
    {
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .OnThrow("/connect/token", new HttpRequestException("connection reset"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheClientTimesOut_FailsAsUnavailableRatherThanAsCancelled()
    {
        // What HttpClient throws on its own timeout is an OperationCanceledException, which reads as
        // the caller having given up when nobody did.
        var handler = new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .OnThrow("/connect/token", new TaskCanceledException("timed out", new TimeoutException()));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => Build(handler).AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unavailable, failure.Reason);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheCallerCancels_ThrowsOperationCanceled()
    {
        // Not wrapped in a ClientAuthenticationException: a cancelled request is not a failed one, and
        // an error handler already classifies cancellation on its own.
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Build(Provider()).AuthenticateAsync(Parameters(), cancellation.Token));
    }

    [Fact]
    public void GetHttpClient_WhenNoClientWasSuppliedAndItWasNotOverridden_Throws()
    {
        var authenticator = new SubclassWithoutAClient(new TestTokenCache());

        Assert.Throws<InvalidOperationException>(authenticator.ResolveClient);
    }

    private static StubHttpMessageHandler Provider()
    {
        return new StubHttpMessageHandler()
            .On(".well-known", HttpStatusCode.OK, Metadata)
            .On("/connect/token", HttpStatusCode.OK, IssuedToken);
    }

    private static ClientCredentialsAuthenticator Build(
        StubHttpMessageHandler handler,
        ClientCredentialsAuthenticatorOptions? options = null)
    {
        return new ClientCredentialsAuthenticator(handler.CreateClient(), new TestTokenCache(), options);
    }

    private static ClientAuthenticationParameters Parameters(
        string? authority = Authority,
        string? clientId = "svc",
        string? clientSecret = "s3cret",
        IReadOnlyList<string>? scopes = null,
        IReadOnlyList<string>? resources = null)
    {
        return new ClientAuthenticationParameters
        {
            Authority = authority,
            ClientId = clientId,
            ClientSecret = clientSecret,
            Scopes = scopes,
            Resources = resources,
        };
    }

    private sealed class SubclassWithoutAClient(IClientAuthenticationCache cache)
        : ClientCredentialsAuthenticator(cache)
    {
        public void ResolveClient()
        {
            this.GetHttpClient();
        }
    }
}
