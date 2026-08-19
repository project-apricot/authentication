using System.Globalization;
using System.Text;

namespace ApricotFramework.Authentication;

/// <summary>
/// Builds the cache keys that identify a token and a discovered endpoint.
/// </summary>
/// <remarks>
/// Shared rather than private to a cache because the authenticator keys concurrent callers by the same
/// value, and because a cache of your own must produce keys that collide exactly when two parameter
/// sets deserve the same token — no more often.
/// </remarks>
public static class ClientAuthenticationKeys
{
    /// <summary>
    /// Distinguishes a token entry from anything else sharing the cache.
    /// </summary>
    private const string TokenKeyPrefix = "apricot-auth-token|";

    /// <summary>
    /// Distinguishes a discovered-endpoint entry from anything else sharing the cache.
    /// </summary>
    private const string TokenEndpointKeyPrefix = "apricot-auth-endpoint|";

    /// <summary>
    /// Builds the key a token for these parameters is cached under.
    /// </summary>
    /// <param name="parameters">The parameters the token is obtained for.</param>
    /// <returns>A key equal for two parameter sets exactly when they deserve the same token.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="parameters"/> is null.</exception>
    /// <remarks>
    /// The secret is deliberately not part of the key. Including it would discard every valid token the
    /// moment a secret rotated, and would write a credential into whatever the cache is backed by.
    /// </remarks>
    public static string ForToken(ClientAuthenticationParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var builder = new StringBuilder(TokenKeyPrefix);

        AppendSegment(builder, parameters.Authority);
        AppendSegment(builder, parameters.ClientId);

        // Sorted, so callers listing the same scopes in a different order share one entry. Ordinally,
        // so the key cannot vary with the thread's culture.
        foreach (var scope in Sorted(parameters.Scopes))
        {
            builder.Append('s');
            AppendSegment(builder, scope);
        }

        foreach (var resource in Sorted(parameters.Resources))
        {
            builder.Append('r');
            AppendSegment(builder, resource);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Builds the key an authority's token endpoint is cached under.
    /// </summary>
    /// <param name="authority">The authority whose metadata was read.</param>
    /// <returns>The key for that authority.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="authority"/> is null.</exception>
    public static string ForTokenEndpoint(string authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var builder = new StringBuilder(TokenEndpointKeyPrefix);

        AppendSegment(builder, authority);

        return builder.ToString();
    }

    /// <summary>
    /// Orders a list of protocol tokens, treating an absent list as empty.
    /// </summary>
    /// <param name="values">The values to order.</param>
    /// <returns>The values in ordinal order.</returns>
    private static IEnumerable<string> Sorted(IReadOnlyList<string>? values)
    {
        return values is null ? [] : values.Order(StringComparer.Ordinal);
    }

    /// <summary>
    /// Appends one value such that no value can imitate the surrounding structure.
    /// </summary>
    /// <param name="builder">The key being built.</param>
    /// <param name="value">The value to append, which may be absent.</param>
    private static void AppendSegment(StringBuilder builder, string? value)
    {
        // Length-prefixed rather than delimiter-joined: under a delimiter the scopes "a-b" and
        // "a", "b" produce one key, and a token minted for either is then served for both.
        if (value is null)
        {
            builder.Append("-|");
            return;
        }

        builder
            .Append(value.Length.ToString(CultureInfo.InvariantCulture))
            .Append(':')
            .Append(value)
            .Append('|');
    }
}
