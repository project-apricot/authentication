using System.Security.Claims;

namespace ApricotFramework.Authentication.AspNetCore.Model;

/// <summary>
/// Who a request is from, read out of a validated token.
/// </summary>
/// <remarks>
/// One type for both a person and a service. Which of <see cref="Subject"/> and <see cref="ClientId"/>
/// is present is the provider's choice, not a reliable way to tell the two apart: a machine token has no
/// subject under RFC 9068, and one under Azure AD, Auth0 and Keycloak.
/// </remarks>
public class AuthenticatedPrincipal
{
    /// <summary>
    /// Gets the subject the token was issued for, when it names one.
    /// </summary>
    /// <remarks>
    /// Absent for a service-to-service token from a provider that follows RFC 9068, since a client
    /// credentials grant has no resource owner to name.
    /// </remarks>
    public string? Subject { get; init; }

    /// <summary>
    /// Gets the client the token was issued to, when it names one.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// Gets the scopes the token was granted.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>
    /// Gets everything else the token asserted.
    /// </summary>
    /// <remarks>
    /// The same instance as <c>HttpContext.User</c>. Read anything this type does not surface from here
    /// rather than parsing the token again.
    /// </remarks>
    public required ClaimsPrincipal Claims { get; init; }
}
