using ApricotFramework.Authentication;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.Tests;

public class BaseClientAuthenticatorTests
{
    [Fact]
    public async Task DoAuthenticatedAsync_PassesTheObtainedToken()
    {
        var authenticator = Authenticator();

        var seen = await authenticator.DoAuthenticatedAsync(
            (context, _) => Task.FromResult(context.Token),
            Parameters(),
            TestContext.Current.CancellationToken);

        Assert.Equal("at-1", seen);
    }

    [Fact]
    public async Task DoAuthenticatedAsync_WhenTheOperationThrows_LeavesTheExceptionAlone()
    {
        // The predecessor wrapped the whole call, so a downstream failure was reported as an
        // authentication failure and answered with the wrong status.
        var authenticator = Authenticator();

        await Assert.ThrowsAsync<InvalidTimeZoneException>(() => authenticator.DoAuthenticatedAsync<string>(
            (_, _) => throw new InvalidTimeZoneException("the downstream call failed"),
            Parameters(),
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DoAuthenticatedAsync_WithoutAnOperation_Throws()
    {
        var authenticator = Authenticator();

        await Assert.ThrowsAsync<ArgumentNullException>(() => authenticator.DoAuthenticatedAsync<string>(
            null!,
            Parameters(),
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheFetchThrowsSomethingUnexpected_ReportsItAsUnknown()
    {
        var authenticator = new StubAuthenticator(
            new TestTokenCache(),
            _ => throw new InvalidTimeZoneException("something unrelated"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.Unknown, failure.Reason);
        Assert.IsType<InvalidTimeZoneException>(failure.InnerException);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenTheFetchAlreadyClassifiedTheFailure_KeepsThatReason()
    {
        var authenticator = new StubAuthenticator(
            new TestTokenCache(),
            _ => throw new ClientAuthenticationException(
                ClientAuthenticationFailure.InvalidCredentials,
                "rejected"));

        var failure = await Assert.ThrowsAsync<ClientAuthenticationException>(
            () => authenticator.AuthenticateAsync(Parameters(), TestContext.Current.CancellationToken));

        Assert.Equal(ClientAuthenticationFailure.InvalidCredentials, failure.Reason);
        Assert.Null(failure.InnerException);
    }

    [Fact]
    public async Task AuthenticateAsync_WithoutParameters_UsesWhatTheSubclassSupplies()
    {
        var authenticator = new SubclassWithDefaults(new TestTokenCache());

        await authenticator.AuthenticateAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("https://configured.example.com", authenticator.LastParameters?.Authority);
        Assert.Equal("configured", authenticator.LastParameters?.ClientId);
    }

    [Fact]
    public void Constructor_WithoutACache_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new StubAuthenticator(null!, _ => Task.FromResult(Context())));
    }

    private static StubAuthenticator Authenticator()
    {
        return new StubAuthenticator(new TestTokenCache(), _ => Task.FromResult(Context()));
    }

    private static AuthenticatedClientContext Context()
    {
        return new AuthenticatedClientContext { Token = "at-1" };
    }

    private static ClientAuthenticationParameters Parameters()
    {
        return new ClientAuthenticationParameters
        {
            Authority = "https://idp.example.com",
            ClientId = "svc",
        };
    }

    private class StubAuthenticator(
        IClientAuthenticationCache cache,
        Func<ClientAuthenticationParameters, Task<AuthenticatedClientContext>> fetch)
        : BaseClientAuthenticator(cache)
    {
        public ClientAuthenticationParameters? LastParameters { get; private set; }

        protected override Task<AuthenticatedClientContext> GetTokenAndCacheAsync(
            ClientAuthenticationParameters parameters,
            CancellationToken cancellationToken)
        {
            this.LastParameters = parameters;

            return fetch(parameters);
        }
    }

    private sealed class SubclassWithDefaults(IClientAuthenticationCache cache)
        : StubAuthenticator(cache, _ => Task.FromResult(Context()))
    {
        protected override ClientAuthenticationParameters GetEffectiveParameters(ClientAuthenticationParameters? input)
        {
            return new ClientAuthenticationParameters
            {
                Authority = input?.Authority ?? "https://configured.example.com",
                ClientId = input?.ClientId ?? "configured",
            };
        }
    }
}
