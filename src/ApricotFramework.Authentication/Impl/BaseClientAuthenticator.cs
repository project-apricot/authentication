using System.Collections.Concurrent;

namespace ApricotFramework.Authentication.Impl;

/// <summary>
/// Reads the cache, coalesces concurrent misses, and classifies whatever the fetch threw.
/// </summary>
/// <remarks>
/// Subclasses supply only <see cref="GetTokenAndCacheAsync"/> — how a token is actually obtained, and
/// how long it is worth keeping.
/// </remarks>
public abstract class BaseClientAuthenticator : IClientAuthenticator
{
    /// <summary>
    /// The fetches in progress, keyed as the cache keys them, so a miss is requested once.
    /// </summary>
    private readonly ConcurrentDictionary<string, Lazy<Task<AuthenticatedClientContext>>> inFlight =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="BaseClientAuthenticator"/> class.
    /// </summary>
    /// <param name="cache">Where obtained tokens are kept.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cache"/> is null.</exception>
    protected BaseClientAuthenticator(IClientAuthenticationCache cache)
    {
        ArgumentNullException.ThrowIfNull(cache);

        this.Cache = cache;
    }

    /// <summary>
    /// Gets where obtained tokens are kept.
    /// </summary>
    protected IClientAuthenticationCache Cache { get; }

    /// <inheritdoc />
    public virtual async Task<AuthenticatedClientContext> AuthenticateAsync(
        ClientAuthenticationParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        // Checked up front, because a fetch that completes synchronously would otherwise satisfy an
        // already-canceled caller instead of observing the cancellation.
        cancellationToken.ThrowIfCancellationRequested();

        var effective = this.GetEffectiveParameters(parameters);

        var cached = await this.Cache.GetTokenAsync(effective, cancellationToken).ConfigureAwait(false);

        return cached ?? await this.FetchCoalescedAsync(effective, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public virtual async Task<T> DoAuthenticatedAsync<T>(
        Func<AuthenticatedClientContext, CancellationToken, Task<T>> securedOperation,
        ClientAuthenticationParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securedOperation);

        var context = await this.AuthenticateAsync(parameters, cancellationToken).ConfigureAwait(false);

        return await securedOperation(context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Obtains a token and caches it.
    /// </summary>
    /// <param name="parameters">The effective parameters, with nothing left to fill in.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The token obtained.</returns>
    /// <remarks>
    /// Caching is the implementation's, not this class's, because only it knows what the provider said
    /// about expiry and how much of that margin to keep back.
    /// </remarks>
    protected abstract Task<AuthenticatedClientContext> GetTokenAndCacheAsync(
        ClientAuthenticationParameters parameters,
        CancellationToken cancellationToken);

    /// <summary>
    /// Fills in whatever the caller left unset.
    /// </summary>
    /// <param name="input">What the caller asked for, which may be absent entirely.</param>
    /// <returns>The parameters to obtain a token with.</returns>
    /// <remarks>
    /// Returns the input unchanged here; an authenticator built over configuration overrides this to
    /// supply the service's own authority and credentials.
    /// </remarks>
    protected virtual ClientAuthenticationParameters GetEffectiveParameters(ClientAuthenticationParameters? input)
    {
        return input ?? new ClientAuthenticationParameters();
    }

    /// <summary>
    /// Requests a token or joins the request already running for these parameters.
    /// </summary>
    /// <param name="effective">The effective parameters.</param>
    /// <param name="cancellationToken">The token to cancel waiting with.</param>
    /// <returns>The token obtained.</returns>
    private async Task<AuthenticatedClientContext> FetchCoalescedAsync(
        ClientAuthenticationParameters effective,
        CancellationToken cancellationToken)
    {
        var key = ClientAuthenticationKeys.ForToken(effective);

        // Lazy, because GetOrAdd may run its factory more than once under contention and a discarded
        // Task would be a token request nobody is waiting for.
        var pending = this.inFlight.GetOrAdd(
            key,
            _ => new Lazy<Task<AuthenticatedClientContext>>(
                () => this.FetchAndClassifyAsync(effective),
                LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            // Awaited through WaitAsync so that a caller giving up abandons its own wait rather than
            // cancelling the request the other callers are still waiting on.
            return await pending.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (pending.Value.IsCompleted)
            {
                this.inFlight.TryRemove(KeyValuePair.Create(key, pending));
            }
        }
    }

    /// <summary>
    /// Gets a token, reporting anything unexpected as a client authentication failure.
    /// </summary>
    /// <param name="effective">The effective parameters.</param>
    /// <returns>The token obtained.</returns>
    private async Task<AuthenticatedClientContext> FetchAndClassifyAsync(ClientAuthenticationParameters effective)
    {
        try
        {
            // Not the caller's token: this request is shared, and the caller waiting on it may leave.
            return await this.GetTokenAndCacheAsync(effective, CancellationToken.None).ConfigureAwait(false);
        }
        catch (ClientAuthenticationException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new ClientAuthenticationException(
                ClientAuthenticationFailure.Unknown,
                $"Could not obtain a token for client '{effective.ClientId}' from '{effective.Authority}'.",
                exception);
        }
    }
}
