using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using ApricotFramework.Authentication.AspNetCore.Exceptions;
using ApricotFramework.Authentication.AspNetCore.Model;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.AspNetCore.Extensions;

/// <summary>
/// Reads the principal a validated token describes.
/// </summary>
public static class HttpContextAuthenticationExtensions
{
    /// <summary>
    /// The subject claim, as RFC 9068 names it.
    /// </summary>
    private const string SubjectClaim = "sub";

    /// <summary>
    /// The scope claim, as RFC 9068 names it.
    /// </summary>
    private const string ScopeClaim = "scope";

    /// <summary>
    /// The claims a provider may name the calling client in, most standard first.
    /// </summary>
    /// <remarks>
    /// <c>client_id</c> is RFC 9068 and IdentityServer; <c>azp</c> is Auth0, Keycloak and Google;
    /// <c>appid</c> is Azure AD v1. Reading all three is what makes the client identity portable.
    /// </remarks>
    private static readonly string[] ClientClaims = ["client_id", "azp", "appid"];

    /// <summary>
    /// Gets the principal the request is authenticated as.
    /// </summary>
    /// <param name="httpContext">The request being handled.</param>
    /// <returns>The principal.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpContext"/> is null.</exception>
    /// <exception cref="NotAuthenticatedException">Thrown when the request carries no principal.</exception>
    /// <remarks>
    /// Requires only that the request is authenticated. It does not require a subject, because a
    /// service-to-service token legitimately has none.
    /// </remarks>
    public static AuthenticatedPrincipal GetPrincipal(this HttpContext httpContext)
    {
        return httpContext.TryGetPrincipal(out var principal)
            ? principal
            : throw new NotAuthenticatedException("The request carries no authenticated principal.");
    }

    /// <summary>
    /// Gets the principal the request is authenticated as, if it is authenticated at all.
    /// </summary>
    /// <param name="httpContext">The request being handled.</param>
    /// <param name="principal">The principal, when there is one.</param>
    /// <returns>True when the request is authenticated.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpContext"/> is null.</exception>
    /// <remarks>
    /// For an endpoint that serves anonymous callers differently rather than refusing them, where an
    /// exception would be the ordinary case.
    /// </remarks>
    public static bool TryGetPrincipal(this HttpContext httpContext, [NotNullWhen(true)] out AuthenticatedPrincipal? principal)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var user = httpContext.User;

        if (user.Identity is not { IsAuthenticated: true })
        {
            principal = null;

            return false;
        }

        principal = new AuthenticatedPrincipal
        {
            Subject = FindSubject(user),
            ClientId = FindClient(user),
            Scopes = ReadScopes(user),
            Claims = user,
        };

        return true;
    }

    /// <summary>
    /// Finds the subject, whether inbound claims were mapped to their legacy names.
    /// </summary>
    /// <param name="user">The validated principal.</param>
    /// <returns>The subject, or null.</returns>
    private static string? FindSubject(ClaimsPrincipal user)
    {
        // This package turns claim mapping off, but a host may turn it back on, and then 'sub' has been
        // renamed to the legacy identifier by the time it gets here.
        return Value(user, SubjectClaim) ?? Value(user, ClaimTypes.NameIdentifier);
    }

    /// <summary>
    /// Finds the calling client under whichever claim the provider used.
    /// </summary>
    /// <param name="user">The validated principal.</param>
    /// <returns>The client identifier, or null.</returns>
    private static string? FindClient(ClaimsPrincipal user)
    {
        return ClientClaims.Select(claim => Value(user, claim)).FirstOrDefault(value => value is not null);
    }

    /// <summary>
    /// Reads the granted scopes, in either shape a provider issues them.
    /// </summary>
    /// <param name="user">The validated principal.</param>
    /// <returns>The scopes, which may be empty.</returns>
    private static IReadOnlyList<string> ReadScopes(ClaimsPrincipal user)
    {
        // RFC 9068 makes 'scope' one space-delimited claim; IdentityServer emits one claim per scope.
        // Splitting the values of every match covers both without having to know which provider it is.
        return
        [
            .. user.FindAll(claim => string.Equals(claim.Type, ScopeClaim, StringComparison.Ordinal))
                .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        ];
    }

    /// <summary>
    /// Reads the first value of a claim.
    /// </summary>
    /// <param name="user">The validated principal.</param>
    /// <param name="claimType">The claim to read.</param>
    /// <returns>The value, or null when it is absent or blank.</returns>
    private static string? Value(ClaimsPrincipal user, string claimType)
    {
        var value = user.FindFirst(claim => string.Equals(claim.Type, claimType, StringComparison.Ordinal))?.Value;

        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
