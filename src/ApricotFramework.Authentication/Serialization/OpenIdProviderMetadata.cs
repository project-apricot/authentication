using System.Text.Json.Serialization;

namespace ApricotFramework.Authentication.Serialization;

/// <summary>
/// The two fields of an OpenID provider's metadata document this library needs (RFC 8414).
/// </summary>
internal sealed class OpenIdProviderMetadata
{
    /// <summary>
    /// Gets or sets the issuer identifier the document claims to describe.
    /// </summary>
    /// <remarks>
    /// Checked against the authority that was asked. Without that check, a redirected or substituted
    /// document is trusted to name its own endpoints.
    /// </remarks>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the endpoint tokens are requested from.
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; set; }
}
