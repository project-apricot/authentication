namespace ApricotFramework.Authentication.ClientCredentials;

/// <summary>
/// Gets access tokens for this service acting as itself, under the client credentials grant.
/// </summary>
/// <remarks>
/// Adds nothing to <see cref="ITokenAuthenticator"/>, and exists to be named. A service may hold
/// more than one way of getting a token — as itself, and on behalf of whoever called it — and
/// those are different authorities that happen to share a shape. Separating them by type is what
/// lets both be registered at once and lets a call site say what it means, rather than one
/// silently displacing the other.
/// </remarks>
public interface IClientCredentialsAuthenticator : ITokenAuthenticator;
