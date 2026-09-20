namespace ApricotFramework.Authentication.TokenExchange;

/// <summary>
/// The token representing whoever a service is acting for.
/// </summary>
/// <param name="Value">The token itself, as it was presented.</param>
/// <param name="TokenType">
/// What kind of token it is, as an RFC 8693 token type identifier, or null to let the authenticator
/// assume an access token?
/// </param>
/// <param name="ExpiresAt">
/// When the token stops being valid, where that is known. Supplied by whoever read the token, since
/// only they can say — this library never parses one.
/// </param>
public sealed record SubjectToken(string Value, string? TokenType = null, DateTimeOffset? ExpiresAt = null);
