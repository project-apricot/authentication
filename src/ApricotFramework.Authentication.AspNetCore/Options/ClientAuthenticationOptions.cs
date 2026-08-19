namespace ApricotFramework.Authentication.AspNetCore.Options;

/// <summary>
/// The credentials this service calls other services with, bound from <c>Authentication:Client</c>.
/// </summary>
public class ClientAuthenticationOptions
{
    /// <summary>
    /// How long a token request may take before it is abandoned.
    /// </summary>
    /// <remarks>
    /// The framework default is 100 seconds, which holds a request open long enough for a slow
    /// provider to become an availability problem of its own.
    /// </remarks>
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the provider to obtain tokens from, when it differs from the inbound authority.
    /// </summary>
    /// <remarks>
    /// Unset means the authority tokens are validated against also issues them, which is the usual
    /// arrangement. They differ when a service accepts tokens from one issuer and calls services that
    /// trust another.
    /// </remarks>
    public string? Authority { get; set; }

    /// <summary>
    /// Gets or sets the client identifier this service authenticates as.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the secret that authenticates the client.
    /// </summary>
    /// <remarks>
    /// Supply it through an environment variable or a secrets manager. Bound from configuration, it is
    /// read from wherever the host's configuration comes from and never written anywhere by this
    /// library.
    /// </remarks>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the scopes requested when a caller names none.
    /// </summary>
    public IList<string>? Scopes { get; set; }

    /// <summary>
    /// Gets or sets the resource indicators requested when a caller names none.
    /// </summary>
    public IList<string>? Resources { get; set; }

    /// <summary>
    /// Gets or sets how client credentials are presented to the token endpoint.
    /// </summary>
    /// <remarks>
    /// Not a preference: providers differ in which they accept, and some accept only one.
    /// </remarks>
    public ClientCredentialStyle CredentialStyle { get; set; } = ClientCredentialStyle.Basic;

    /// <summary>
    /// Gets or sets how far before its stated expiry a token stops being served from cache.
    /// </summary>
    public TimeSpan TokenExpirySkew { get; set; } = ClientCredentialsAuthenticatorOptions.DefaultTokenExpirySkew;

    /// <summary>
    /// Gets or sets how long a provider's metadata is reused before it is read again.
    /// </summary>
    /// <remarks>
    /// Separate from the inbound handler's own refresh interval, which governs signing keys rather than
    /// the endpoint a token is requested from.
    /// </remarks>
    public TimeSpan MetadataCacheDuration { get; set; } = ClientCredentialsAuthenticatorOptions.DefaultMetadataCacheDuration;

    /// <summary>
    /// Gets or sets how long a token request may take before it is abandoned.
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = DefaultRequestTimeout;
}
