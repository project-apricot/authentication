namespace ApricotFramework.Authentication;

/// <summary>
/// How the client credentials grant is carried out, independent of who it is carried out as.
/// </summary>
/// <remarks>
/// Not bound from configuration. The ASP.NET Core package projects a settings section onto this, so a
/// host configures it there rather than here.
/// </remarks>
public sealed class ClientCredentialsAuthenticatorOptions
{
    /// <summary>
    /// How far before its stated expiry a token stops being served from cache.
    /// </summary>
    public static readonly TimeSpan DefaultTokenExpirySkew = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long a provider's metadata is reused before it is read again.
    /// </summary>
    public static readonly TimeSpan DefaultMetadataCacheDuration = TimeSpan.FromMinutes(60);

    /// <summary>
    /// Gets or sets how client credentials are presented to the token endpoint.
    /// </summary>
    public ClientCredentialStyle CredentialStyle { get; set; } = ClientCredentialStyle.Basic;

    /// <summary>
    /// Gets or sets how far before its stated expiry a token stops being served from cache.
    /// </summary>
    /// <remarks>
    /// Keeps a token from expiring between being handed out and being used. Too large simply refreshes
    /// more often; larger than the token's own lifetime means nothing is ever cached.
    /// </remarks>
    public TimeSpan TokenExpirySkew { get; set; } = DefaultTokenExpirySkew;

    /// <summary>
    /// Gets or sets how long a provider's metadata is reused before it is read again.
    /// </summary>
    public TimeSpan MetadataCacheDuration { get; set; } = DefaultMetadataCacheDuration;

    /// <summary>
    /// Gets or sets whether an authority may be reached over plain HTTP.
    /// </summary>
    /// <remarks>
    /// Covers the scheme only. Accepting an untrusted certificate over HTTPS is the message handler's
    /// concern, so a host enabling this has to relax both to reach a development provider.
    /// </remarks>
    public bool AllowInsecureAuthority { get; set; }
}
