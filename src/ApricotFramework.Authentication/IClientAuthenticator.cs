namespace ApricotFramework.Authentication;

/// <summary>
/// Obtains access tokens for calls this service makes to another.
/// </summary>
public interface IClientAuthenticator
{
    /// <summary>
    /// Obtains a token, reusing a cached one while it is still good.
    /// </summary>
    /// <param name="parameters">
    /// What differs from the configured default, or <see langword="null"/> for the default alone.
    /// </param>
    /// <param name="cancellationToken">The token to cancel the request with.</param>
    /// <returns>The token to present, and what is known about it.</returns>
    /// <exception cref="ClientAuthenticationException">Thrown when no token could be obtained.</exception>
    Task<AuthenticatedClientContext> AuthenticateAsync(ClientAuthenticationParameters? parameters = null, CancellationToken cancellationToken = default);

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
    /// <exception cref="ClientAuthenticationException">
    /// Thrown when no token could be obtained. Anything the operation itself throws is left alone.
    /// </exception>
    Task<T> DoAuthenticatedAsync<T>(
        Func<AuthenticatedClientContext, CancellationToken, Task<T>> securedOperation,
        ClientAuthenticationParameters? parameters = null,
        CancellationToken cancellationToken = default);
}
