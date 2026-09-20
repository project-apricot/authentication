using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ApricotFramework.Authentication.Caching;

/// <summary>
/// Builds the cache keys that identify a token and a discovered endpoint.
/// </summary>
/// <remarks>
/// Shared rather than private to a cache because the authenticator keys concurrent callers by the same
/// value, and because a cache of your own must produce keys that collide exactly when two-parameter
/// sets deserve the same token — no more often.
/// </remarks>
public static class TokenCacheKeys
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
    /// moment a secret rotated and would write a credential into whatever the cache is backed by.
    /// </remarks>
    public static string ForToken(TokenRequestParameters parameters)
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

        foreach (var audience in Sorted(parameters.Audiences))
        {
            builder.Append('a');
            AppendSegment(builder, audience);
        }

        // Every remaining field that changes which token comes back, whichever grant sends it. Kept
        // here rather than left to each grant to contribute, so that a grant added later is keyed
        // correctly without its author having thought about caching: forgetting the subject is not a
        // stale entry, it is one subject's token served to the next.
        AppendTagged(builder, 't', parameters.SubjectTokenType);
        AppendTagged(builder, 'q', parameters.RequestedTokenType);
        AppendTagged(builder, 'w', parameters.ActorTokenType);

        // Hashed, not omitted. The secret is left out entirely because rotating it must not discard
        // valid tokens; these are the opposite — a different subject token is a different subject or
        // a different session, and serving the old entry would be the bug.
        AppendDigest(builder, 'u', parameters.SubjectToken);
        AppendDigest(builder, 'v', parameters.ActorToken);

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
    /// Appends a tagged value or nothing when it is absent.
    /// </summary>
    /// <param name="builder">The key being built.</param>
    /// <param name="tag">The letter distinguishing this field from every other.</param>
    /// <param name="value">The value, which may be absent.</param>
    /// <remarks>
    /// Absence is unambiguous because the tag is only written when there is a value, and a value
    /// cannot contain a tag position: every segment is length prefixed.
    /// </remarks>
    private static void AppendTagged(StringBuilder builder, char tag, string? value)
    {
        if (value is null)
        {
            return;
        }

        builder.Append(tag);
        AppendSegment(builder, value);
    }

    /// <summary>
    /// Appends a digest of a value that is itself a credential, or nothing when it is absent.
    /// </summary>
    /// <param name="builder">The key being built.</param>
    /// <param name="tag">The letter distinguishing this field from every other.</param>
    /// <param name="secret">The credential, which may be absent.</param>
    /// <remarks>
    /// A cache key reaches places the token itself should not — a log line, a dump, whatever backs a
    /// distributed cache — so the key carries a digest and the token stays in the value.
    /// </remarks>
    private static void AppendDigest(StringBuilder builder, char tag, string? secret)
    {
        if (secret is null)
        {
            return;
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(secret));

        builder.Append(tag);
        AppendSegment(builder, Convert.ToBase64String(digest));
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
