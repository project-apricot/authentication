using ApricotFramework.Authentication.ClientCredentials;
using ApricotFramework.Authentication.Impl;
using ApricotFramework.Authentication.TokenExchange;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// Covers the type graph itself, because the markers only mean anything if each authenticator wears
/// exactly one.
/// </summary>
public class GrantMarkerTests
{
    [Fact]
    public void TokenExchangeAuthenticator_IsNotAClientCredentialsAuthenticator()
    {
        // The one that has to hold. It failed once: the shared base declared the client credentials
        // marker, so every subclass inherited it and a container registering by implemented
        // interfaces would hand a caller the exchange where it asked for the service's own token —
        // which is the escalation the split exists to prevent.
        Assert.False(typeof(IClientCredentialsAuthenticator).IsAssignableFrom(typeof(TokenExchangeAuthenticator)));
    }

    [Fact]
    public void ClientCredentialsAuthenticator_IsNotATokenExchangeAuthenticator()
    {
        Assert.False(typeof(ITokenExchangeAuthenticator).IsAssignableFrom(typeof(ClientCredentialsAuthenticator)));
    }

    [Fact]
    public void TheSharedBase_WearsNoGrantMarkerAtAll()
    {
        // Anything it declared would be inherited by every grant built on it, now and later.
        Assert.False(typeof(IClientCredentialsAuthenticator).IsAssignableFrom(typeof(CachingTokenAuthenticator)));
        Assert.False(typeof(ITokenExchangeAuthenticator).IsAssignableFrom(typeof(CachingTokenAuthenticator)));
        Assert.True(typeof(ITokenAuthenticator).IsAssignableFrom(typeof(CachingTokenAuthenticator)));
    }

    [Theory]
    [InlineData(typeof(ClientCredentialsAuthenticator), typeof(IClientCredentialsAuthenticator))]
    [InlineData(typeof(TokenExchangeAuthenticator), typeof(ITokenExchangeAuthenticator))]
    public void EachGrant_WearsItsOwnMarker(Type authenticator, Type marker)
    {
        Assert.True(marker.IsAssignableFrom(authenticator));
    }

    [Theory]
    [InlineData(typeof(IClientCredentialsAuthenticator))]
    [InlineData(typeof(ITokenExchangeAuthenticator))]
    public void EveryMarker_IsATokenAuthenticator(Type marker)
    {
        // So a caller that does not care which grant it gets can still ask for one.
        Assert.True(typeof(ITokenAuthenticator).IsAssignableFrom(marker));
    }
}
