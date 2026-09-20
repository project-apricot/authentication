namespace ApricotFramework.Authentication;

/// <summary>
/// Gets access tokens for calls this service makes to another.
/// </summary>
/// <remarks>
/// Says only that a token can be had and how to ask for one; which OAuth grant produces it is the
/// implementation's business. Code that needs a credential rather than a particular provenance — a
/// transport attaching a header, say — depends on this and stays indifferent to how the token was
/// obtained.
/// </remarks>
public interface ITokenAuthenticator
{
    /// <summary>
    /// Gets a token, reusing a cached one while it is still good.
    /// </summary>
    /// <param name="parameters">
    /// What differs from the configured default, or <see langword="null"/> for the default alone.
    /// </param>
    /// <param name="cancellationToken">The token to cancel the request with.</param>
    /// <returns>The token to present, and what is known about it.</returns>
    /// <exception cref="TokenRequestException">Thrown when no token could be obtained.</exception>
    Task<AccessToken> AuthenticateAsync(TokenRequestParameters? parameters = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs an operation with a token obtained for it.
    /// </summary>
    /// <typeparam name="T">What the operation returns.</typeparam>
    /// <param name="securedOperation">The operation to run.</param>
    /// <param name="parameters">
    /// What differs from the configured default, or <see langword="null"/> for the default alone.
    /// </param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>Whatever the operation returned.</returns>
    /// <exception cref="TokenRequestException">
    /// Thrown when no token could be obtained. Anything the operation itself throws is left alone.
    /// </exception>
    Task<T> DoAuthenticatedAsync<T>(
        Func<AccessToken, CancellationToken, Task<T>> securedOperation,
        TokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default);
}
