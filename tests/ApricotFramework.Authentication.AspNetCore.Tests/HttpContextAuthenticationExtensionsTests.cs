using System.Security.Claims;
using ApricotFramework.Authentication.AspNetCore.Exceptions;
using ApricotFramework.Authentication.AspNetCore.Extensions;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class HttpContextAuthenticationExtensionsTests
{
    [Fact]
    public void GetPrincipal_WithAServiceTokenCarryingNoSubject_StillReturnsThePrincipal()
    {
        // The bug this replaces: a client credentials grant has no resource owner, so IdentityServer
        // emits no 'sub', and requiring one threw on exactly the tokens this library issues.
        var context = Context(new Claim("client_id", "orders-service"), new Claim("scope", "orders.read"));

        var principal = context.GetPrincipal();

        Assert.Null(principal.Subject);
        Assert.Equal("orders-service", principal.ClientId);
        Assert.Equal(["orders.read"], principal.Scopes);
    }

    [Fact]
    public void GetPrincipal_WithAUserToken_ReturnsTheSubject()
    {
        var context = Context(new Claim("sub", "user-42"), new Claim("client_id", "web-app"));

        var principal = context.GetPrincipal();

        Assert.Equal("user-42", principal.Subject);
        Assert.Equal("web-app", principal.ClientId);
    }

    [Fact]
    public void GetPrincipal_WhenTheRequestIsNotAuthenticated_Throws()
    {
        Assert.Throws<NotAuthenticatedException>(() => Anonymous().GetPrincipal());
    }

    [Fact]
    public void GetPrincipal_WhenThereIsNoUserAtAll_Throws()
    {
        var context = new DefaultHttpContext();

        Assert.Throws<NotAuthenticatedException>(() => context.GetPrincipal());
    }

    [Fact]
    public void TryGetPrincipal_WhenTheRequestIsNotAuthenticated_ReturnsFalse()
    {
        Assert.False(Anonymous().TryGetPrincipal(out var principal));
        Assert.Null(principal);
    }

    [Fact]
    public void TryGetPrincipal_WhenTheRequestIsAuthenticated_ReturnsTrue()
    {
        Assert.True(Context(new Claim("sub", "user-42")).TryGetPrincipal(out var principal));
        Assert.Equal("user-42", principal.Subject);
    }

    [Theory]
    [InlineData("client_id")]
    [InlineData("azp")]
    [InlineData("appid")]
    public void GetPrincipal_ReadsTheClientFromWhicheverClaimTheProviderUsed(string claimType)
    {
        // client_id is RFC 9068 and IdentityServer, azp is Auth0 and Keycloak, appid is Azure AD v1.
        var principal = Context(new Claim(claimType, "orders-service")).GetPrincipal();

        Assert.Equal("orders-service", principal.ClientId);
    }

    [Fact]
    public void GetPrincipal_WhenSeveralClientClaimsArePresent_PrefersTheStandardOne()
    {
        var principal = Context(new Claim("azp", "from-azp"), new Claim("client_id", "from-client-id")).GetPrincipal();

        Assert.Equal("from-client-id", principal.ClientId);
    }

    [Fact]
    public void GetPrincipal_WithASpaceDelimitedScopeClaim_SplitsIt()
    {
        // The shape RFC 9068 defines.
        var principal = Context(new Claim("scope", "orders.read orders.write billing.read")).GetPrincipal();

        Assert.Equal(["orders.read", "orders.write", "billing.read"], principal.Scopes);
    }

    [Fact]
    public void GetPrincipal_WithOneClaimPerScope_CollectsThemAll()
    {
        // The shape IdentityServer emits.
        var principal = Context(new Claim("scope", "orders.read"), new Claim("scope", "orders.write")).GetPrincipal();

        Assert.Equal(["orders.read", "orders.write"], principal.Scopes);
    }

    [Fact]
    public void GetPrincipal_WithNoScopeClaim_ReportsNoScopes()
    {
        Assert.Empty(Context(new Claim("sub", "user-42")).GetPrincipal().Scopes);
    }

    [Fact]
    public void GetPrincipal_WithABlankSubject_ReportsNoSubject()
    {
        Assert.Null(Context(new Claim("sub", "   ")).GetPrincipal().Subject);
    }

    [Fact]
    public void GetPrincipal_WhenTheHostMappedInboundClaims_StillFindsTheSubject()
    {
        // This package turns mapping off, but a host may turn it back on, and then 'sub' has been
        // renamed to the legacy identifier before it gets here.
        var principal = Context(new Claim(ClaimTypes.NameIdentifier, "user-42")).GetPrincipal();

        Assert.Equal("user-42", principal.Subject);
    }

    [Fact]
    public void GetPrincipal_ExposesTheSamePrincipalTheRequestCarried()
    {
        var context = Context(new Claim("sub", "user-42"), new Claim("email", "someone@example.com"));

        var principal = context.GetPrincipal();

        Assert.Same(context.User, principal.Claims);
        Assert.Equal("someone@example.com", principal.Claims.FindFirst("email")?.Value);
    }

    [Fact]
    public void TryGetPrincipal_WithoutAContext_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HttpContextAuthenticationExtensions.TryGetPrincipal(null!, out _));
    }

    private static DefaultHttpContext Context(params Claim[] claims)
    {
        // A named authentication type is what makes the identity count as authenticated.
        return new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer")),
        };
    }

    private static DefaultHttpContext Anonymous()
    {
        return new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity()),
        };
    }
}
