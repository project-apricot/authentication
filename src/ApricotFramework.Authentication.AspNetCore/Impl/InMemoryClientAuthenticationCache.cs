using Microsoft.Extensions.Caching.Memory;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <summary>
/// Keeps tokens and discovered endpoints in the host's memory cache.
/// </summary>
/// <remarks>
/// Process-local, so each instance of a service obtains its own tokens. That is the right default —
/// it needs no shared infrastructure and leaks no credentials between hosts — and a distributed
/// implementation can replace it by registering <see cref="IClientAuthenticationCache"/> first.
/// </remarks>
public class InMemoryClientAuthenticationCache : IClientAuthenticationCache
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryClientAuthenticationCache"/> class.
    /// </summary>
    /// <param name="cache">The host's memory cache.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cache"/> is null.</exception>
    public InMemoryClientAuthenticationCache(IMemoryCache cache)
    {
        ArgumentNullException.ThrowIfNull(cache);

        this.Cache = cache;
    }

    /// <summary>
    /// Gets the host's memory cache.
    /// </summary>
    protected IMemoryCache Cache { get; }

    /// <inheritdoc />
    public virtual ValueTask<AuthenticatedClientContext?> GetTokenAsync(
        ClientAuthenticationParameters parameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        return ValueTask.FromResult(
            this.Cache.Get<AuthenticatedClientContext>(ClientAuthenticationKeys.ForToken(parameters)));
    }

    /// <inheritdoc />
    public virtual ValueTask SetTokenAsync(
        ClientAuthenticationParameters parameters,
        AuthenticatedClientContext context,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(context);

        this.Cache.Set(ClientAuthenticationKeys.ForToken(parameters), context, expiresAt);

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public virtual ValueTask<string?> GetTokenEndpointAsync(
        string authority,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);

        return ValueTask.FromResult(
            this.Cache.Get<string>(ClientAuthenticationKeys.ForTokenEndpoint(authority)));
    }

    /// <inheritdoc />
    public virtual ValueTask SetTokenEndpointAsync(
        string authority,
        string tokenEndpoint,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);

        this.Cache.Set(ClientAuthenticationKeys.ForTokenEndpoint(authority), tokenEndpoint, expiresAt);

        return ValueTask.CompletedTask;
    }
}
