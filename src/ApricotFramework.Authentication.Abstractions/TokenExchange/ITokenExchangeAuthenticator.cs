namespace ApricotFramework.Authentication.TokenExchange;

/// <summary>
/// Gets access tokens on behalf of the subject a caller arrived as, under the token exchange
/// grant of RFC 8693.
/// </summary>
/// <remarks>
/// Adds nothing to <see cref="ITokenAuthenticator"/>, and exists to be named — see
/// <see cref="ClientCredentials.IClientCredentialsAuthenticator"/> for why the two are separate types. The distinction is not
/// cosmetic: a token obtained this way carries the subject of the token presented to this service,
/// so it bears somebody else's authority and is cached per subject rather than per service.
/// </remarks>
public interface ITokenExchangeAuthenticator : ITokenAuthenticator;
