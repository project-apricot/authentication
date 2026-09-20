using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using ApricotFramework.Authentication.TokenExchange;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.AspNetCore.TokenExchange;

/// <summary>
/// Supplies the token the request being served arrived with, as the subject of an exchange.
/// </summary>
/// <remarks>
/// <para>
/// This is what makes an exchange act for the caller rather than for the service: the credential
/// handed downstream descends from the one the caller presented, so the downstream sees whoever
/// reached this service and not this service itself.
/// </para>
/// <para>
/// Only an authenticated request yields a subject. An <c>Authorization</c> header alone is a string
/// somebody sent us; requiring that the handler already validated it means what goes out has been
/// checked here first, and means the claims below can be read at face value.
/// </para>
/// <para>
/// The raw token is taken off the header rather than from the authentication properties.
/// The bearer handler is not asked to save it — <c>GetTokenAsync("access_token")</c> returns nothing
/// unless a host sets <c>SaveToken</c>, and depending on that would make this work or not work
/// according to a setting, nothing else here reads.
/// </para>
/// </remarks>
public class HttpContextSubjectTokenProvider : ISubjectTokenProvider
{
    /// <summary>
    /// The scheme a bearer token is presented under, per RFC 6750.
    /// </summary>
    private const string BearerScheme = "Bearer";

    /// <summary>
    /// The expiry claim, as RFC 9068 names it.
    /// </summary>
    private const string ExpiryClaim = "exp";

    /// <summary>
    /// Where the request being served is read from.
    /// </summary>
    private readonly IHttpContextAccessor httpContextAccessor;

    /// <summary>
    /// Initializes a new instance of the <see cref="HttpContextSubjectTokenProvider"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">Where the request being served is read from.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpContextAccessor"/> is null.</exception>
    public HttpContextSubjectTokenProvider(IHttpContextAccessor httpContextAccessor)
    {
        ArgumentNullException.ThrowIfNull(httpContextAccessor);

        this.httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Null whenever there is no authenticated request to act for — outside a request entirely, on an
    /// anonymous one, or on one whose credential is not a bearer token. Never an exception and never a
    /// guess: the authenticator decides what a missing subject means, and for an exchange it means
    /// refusal.
    /// </remarks>
    public ValueTask<SubjectToken?> GetSubjectTokenAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var httpContext = this.httpContextAccessor.HttpContext;

        if (httpContext?.User.Identity is not { IsAuthenticated: true })
        {
            return ValueTask.FromResult<SubjectToken?>(null);
        }

        var header = httpContext.Request.Headers.Authorization.ToString();

        if (!AuthenticationHeaderValue.TryParse(header, out var parsed)
            || !string.Equals(parsed.Scheme, BearerScheme, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return ValueTask.FromResult<SubjectToken?>(null);
        }

        var subject = new SubjectToken(
            parsed.Parameter,
            TokenExchangeTokenTypes.AccessToken,
            ReadExpiry(httpContext.User));

        return ValueTask.FromResult<SubjectToken?>(subject);
    }

    /// <summary>
    /// Reads when the presented token stops being valid.
    /// </summary>
    /// <param name="user">The validated principal.</param>
    /// <returns>The expiry, or null when the token stated none.</returns>
    /// <remarks>
    /// Read from the claims the handler already parsed rather than by decoding the token again: the
    /// value has been validated, and this package has no business knowing how a JWT is laid out.
    /// </remarks>
    private static DateTimeOffset? ReadExpiry(ClaimsPrincipal user)
    {
        var value = user.FindFirst(claim => string.Equals(claim.Type, ExpiryClaim, StringComparison.Ordinal))?.Value;

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}
