namespace ApricotFramework.Authentication;

/// <summary>
/// Identifies which token to get, and on whose behalf.
/// </summary>
/// <remarks>
/// Every member is optional. An authenticator built over configuration fills what is left unset from
/// its own settings, so a caller states only what differs from the service default — usually the
/// scopes or resources one particular downstream call needs.
/// </remarks>
public class ClientAuthenticationParameters
{
    /// <summary>
    /// Gets or sets the issuer to get the token from.
    /// </summary>
    /// <remarks>
    /// The base address of the provider, not its token endpoint — that is discovered.
    /// </remarks>
    public string? Authority { get; set; }

    /// <summary>
    /// Gets or sets the client identifier to authenticate as.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the secret that authenticates the client.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the resource indicators the token is requested for (RFC 8707).
    /// </summary>
    /// <remarks>
    /// Sent as one <c>resource</c> parameter each. A provider that does not implement RFC 8707
    /// ignores them, so an unexpectedly broad token is the failure to watch for rather than an error.
    /// </remarks>
    public IReadOnlyList<string>? Resources { get; set; }

    /// <summary>
    /// Gets or sets the scopes to request.
    /// </summary>
    public IReadOnlyList<string>? Scopes { get; set; }
}
