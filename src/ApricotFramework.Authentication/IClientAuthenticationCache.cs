namespace ApricotFramework.Authentication;

/// <summary>
/// Holds tokens and discovered endpoints between calls.
/// </summary>
/// <remarks>
/// Asynchronous because the useful implementations beyond a process-local one are networked. Build
/// keys with <see cref="ClientAuthenticationKeys"/> rather than inventing a scheme: a key that two
/// different parameter sets can share serves one caller's token to another.
/// </remarks>
public interface IClientAuthenticationCache
{
    /// <summary>
    /// Gets the cached token for these parameters if one is still held.
    /// </summary>
    /// <param name="parameters">The parameters the token was obtained for.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The cached token, or <see langword="null"/>.</returns>
    ValueTask<AuthenticatedClientContext?> GetTokenAsync(
        ClientAuthenticationParameters parameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Caches a token until the given instant.
    /// </summary>
    /// <param name="parameters">The parameters the token was obtained for.</param>
    /// <param name="context">The token to cache.</param>
    /// <param name="expiresAt">
    /// When to stop serving it. Earlier than the token's own expiry, by the configured skew.
    /// </param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    ValueTask SetTokenAsync(
        ClientAuthenticationParameters parameters,
        AuthenticatedClientContext context,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the cached token endpoint for an authority if one is still held.
    /// </summary>
    /// <param name="authority">The authority whose metadata was read.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The cached endpoint, or <see langword="null"/>.</returns>
    ValueTask<string?> GetTokenEndpointAsync(string authority, CancellationToken cancellationToken = default);

    /// <summary>
    /// Caches an authority's token endpoint until the given instant.
    /// </summary>
    /// <param name="authority">The authority whose metadata was read.</param>
    /// <param name="tokenEndpoint">The endpoint it published.</param>
    /// <param name="expiresAt">When to read the metadata again.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    ValueTask SetTokenEndpointAsync(
        string authority,
        string tokenEndpoint,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
