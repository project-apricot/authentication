namespace ApricotFramework.Authentication;

/// <summary>
/// An access token the caller may present, and what is known about it.
/// </summary>
public class AuthenticatedClientContext
{
    /// <summary>
    /// The scheme assumed when a provider names none, which every OAuth 2.0 provider in practice uses.
    /// </summary>
    public const string DefaultTokenType = "Bearer";

    /// <summary>
    /// Gets the access token.
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    /// Gets the scheme the token is presented under, as the provider named it.
    /// </summary>
    /// <remarks>
    /// Use this to build the header rather than hard-coding <c>Bearer</c>: a provider is entitled to
    /// answer with a different case, and an authorization header is compared case-sensitively by
    /// some servers.
    /// </remarks>
    public string TokenType { get; init; } = DefaultTokenType;

    /// <summary>
    /// Gets the instant the token stops being valid, or <see langword="null"/> when the provider did
    /// not say.
    /// </summary>
    /// <remarks>
    /// This is the provider's own expiry, not the moment the token stops being served from cache —
    /// that is deliberately earlier, so a token handed out is never about to expire in flight.
    /// </remarks>
    public DateTimeOffset? ExpiresAt { get; init; }
}
