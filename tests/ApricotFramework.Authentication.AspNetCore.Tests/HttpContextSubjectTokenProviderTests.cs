using System.Globalization;
using System.Security.Claims;
using ApricotFramework.Authentication.AspNetCore.TokenExchange;
using ApricotFramework.Authentication.TokenExchange;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class HttpContextSubjectTokenProviderTests
{
    [Fact]
    public async Task GetSubjectTokenAsync_OnAnAuthenticatedRequest_ReturnsTheBearerItArrivedWith()
    {
        var provider = Provider(Authenticated("header.payload.signature"));

        var subject = await provider.GetSubjectTokenAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(subject);
        Assert.Equal("header.payload.signature", subject.Value);
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, subject.TokenType);
    }

    [Fact]
    public async Task GetSubjectTokenAsync_ReadsTheExpiryFromTheValidatedClaims()
    {
        // From the claims the handler already parsed, not by decoding the token again.
        var expiry = DateTimeOffset.UtcNow.AddMinutes(7).ToUnixTimeSeconds();
        var context = Authenticated("t", new Claim("exp", expiry.ToString(CultureInfo.InvariantCulture)));

        var subject = await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(expiry), subject!.ExpiresAt);
    }

    [Fact]
    public async Task GetSubjectTokenAsync_WithNoExpiryClaim_LeavesTheExpiryUnstated()
    {
        var subject = await Provider(Authenticated("t")).GetSubjectTokenAsync(TestContext.Current.CancellationToken);

        Assert.Null(subject!.ExpiresAt);
    }

    [Fact]
    public async Task GetSubjectTokenAsync_WithAnUnparseableExpiry_LeavesTheExpiryUnstated()
    {
        var context = Authenticated("t", new Claim("exp", "not-a-number"));

        var subject = await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken);

        Assert.Null(subject!.ExpiresAt);
    }

    [Fact]
    public async Task GetSubjectTokenAsync_OutsideARequest_ReturnsNothing()
    {
        var provider = new HttpContextSubjectTokenProvider(new HttpContextAccessor { HttpContext = null });

        Assert.Null(await provider.GetSubjectTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetSubjectTokenAsync_OnAnAnonymousRequest_ReturnsNothing()
    {
        // The header alone is a string somebody sent us. Nothing validated it, so nothing goes out.
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity()) };
        context.Request.Headers.Authorization = "Bearer looks-real";

        Assert.Null(await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetSubjectTokenAsync_WithNoAuthorizationHeader_ReturnsNothing()
    {
        // Authenticated by a cookie, say. There is a caller but no token of theirs to hand on.
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([], "Cookies")) };

        Assert.Null(await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("not a header")]
    public async Task GetSubjectTokenAsync_WithACredentialThatIsNotABearerToken_ReturnsNothing(string header)
    {
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([], "Bearer")) };
        context.Request.Headers.Authorization = header;

        Assert.Null(await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetSubjectTokenAsync_AcceptsTheSchemeInAnyCase()
    {
        // RFC 7235 makes the scheme case insensitive, and clients differ on how they spell it.
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([], "Bearer")) };
        context.Request.Headers.Authorization = "bearer t";

        var subject = await Provider(context).GetSubjectTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal("t", subject!.Value);
    }

    [Fact]
    public async Task GetSubjectTokenAsync_WhenAlreadyCanceled_Throws()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await Provider(Authenticated("t")).GetSubjectTokenAsync(cancellation.Token));
    }

    private static DefaultHttpContext Authenticated(string token, params Claim[] claims)
    {
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer")),
        };

        context.Request.Headers.Authorization = $"Bearer {token}";

        return context;
    }

    private static HttpContextSubjectTokenProvider Provider(HttpContext httpContext)
    {
        return new HttpContextSubjectTokenProvider(new HttpContextAccessor { HttpContext = httpContext });
    }
}
