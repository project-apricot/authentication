using ApricotFramework.Authentication;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// A cache with a clock a test controls, so expiry can be reached without waiting for it.
/// </summary>
internal sealed class TestTokenCache : IClientAuthenticationCache
{
    private readonly Dictionary<string, (object Value, DateTimeOffset ExpiresAt)> entries = new(StringComparer.Ordinal);

    public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;

    public int TokenWrites { get; private set; }

    public int EndpointWrites { get; private set; }

    public ValueTask<AuthenticatedClientContext?> GetTokenAsync(
        ClientAuthenticationParameters parameters,
        CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(this.Get<AuthenticatedClientContext>(ClientAuthenticationKeys.ForToken(parameters)));
    }

    public ValueTask SetTokenAsync(
        ClientAuthenticationParameters parameters,
        AuthenticatedClientContext context,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        this.TokenWrites++;
        this.Set(ClientAuthenticationKeys.ForToken(parameters), context, expiresAt);

        return ValueTask.CompletedTask;
    }

    public ValueTask<string?> GetTokenEndpointAsync(string authority, CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(this.Get<string>(ClientAuthenticationKeys.ForTokenEndpoint(authority)));
    }

    public ValueTask SetTokenEndpointAsync(
        string authority,
        string tokenEndpoint,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        this.EndpointWrites++;
        this.Set(ClientAuthenticationKeys.ForTokenEndpoint(authority), tokenEndpoint, expiresAt);

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Gets the instant the entry for these parameters stops being served.
    /// </summary>
    public DateTimeOffset? ExpiryOf(ClientAuthenticationParameters parameters)
    {
        return this.entries.TryGetValue(ClientAuthenticationKeys.ForToken(parameters), out var entry)
            ? entry.ExpiresAt
            : null;
    }

    private T? Get<T>(string key)
        where T : class
    {
        if (!this.entries.TryGetValue(key, out var entry))
        {
            return null;
        }

        if (entry.ExpiresAt <= this.Now)
        {
            this.entries.Remove(key);

            return null;
        }

        return (T)entry.Value;
    }

    private void Set(string key, object value, DateTimeOffset expiresAt)
    {
        this.entries[key] = (value, expiresAt);
    }
}
