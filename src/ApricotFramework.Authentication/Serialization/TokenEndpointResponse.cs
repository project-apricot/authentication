using System.Text.Json.Serialization;

namespace ApricotFramework.Authentication.Serialization;

/// <summary>
/// What a token endpoint answers, successfully or not (RFC 6749 sections 5.1 and 5.2).
/// </summary>
internal sealed class TokenEndpointResponse
{
    /// <summary>
    /// Gets or sets the issued token.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    /// <summary>
    /// Gets or sets the scheme the token is presented under.
    /// </summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    /// <summary>
    /// Gets or sets the token's lifetime in seconds.
    /// </summary>
    /// <remarks>
    /// Read from a JSON string as well as a number: providers exist that quote it, and refusing those
    /// would be a parse failure rather than the interoperability the spec intends.
    /// </remarks>
    [JsonPropertyName("expires_in")]
    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
    public long? ExpiresIn { get; set; }

    /// <summary>
    /// Gets or sets the scopes actually granted when they differ from those requested.
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>
    /// Gets or sets the error code, present only on a failure.
    /// </summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>
    /// Gets or sets the human-readable error detail.
    /// </summary>
    /// <remarks>
    /// Logged, never returned to a caller: providers routinely echo the request back inside it.
    /// </remarks>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
