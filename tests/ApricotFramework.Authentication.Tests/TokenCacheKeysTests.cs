using System.Globalization;
using ApricotFramework.Authentication.Caching;

namespace ApricotFramework.Authentication.Tests;

public class TokenCacheKeysTests
{
    [Fact]
    public void ForToken_ScopesDifferingOnlyByDelimiter_ProduceDifferentKeys()
    {
        // Joining the scopes into one field made these one entry, so a token minted for "a-b" was
        // served to a caller asking for "a" and "b" as well.
        var joined = TokenCacheKeys.ForToken(Parameters(scopes: ["a-b"]));
        var separate = TokenCacheKeys.ForToken(Parameters(scopes: ["a", "b"]));

        Assert.NotEqual(joined, separate);
    }

    [Fact]
    public void ForToken_ClientIdImitatingAScopeField_ProducesDifferentKey()
    {
        // The forgery a length prefix exists to stop: without one, a client id carrying the field
        // delimiter writes its own scope into the key and is served that scope's token.
        var forged = TokenCacheKeys.ForToken(Parameters(clientId: "svc|sapi", scopes: []));
        var genuine = TokenCacheKeys.ForToken(Parameters(clientId: "svc", scopes: ["api"]));

        Assert.NotEqual(forged, genuine);
    }

    [Fact]
    public void ForToken_ScopeImitatingAResourceField_ProducesDifferentKey()
    {
        var forged = TokenCacheKeys.ForToken(Parameters(scopes: ["api|rdb"]));
        var genuine = TokenCacheKeys.ForToken(Parameters(scopes: ["api"], resources: ["db"]));

        Assert.NotEqual(forged, genuine);
    }

    [Fact]
    public void ForToken_ScopeAndResourceWithSameValue_ProduceDifferentKeys()
    {
        var asScope = TokenCacheKeys.ForToken(Parameters(scopes: ["api"]));
        var asResource = TokenCacheKeys.ForToken(Parameters(resources: ["api"]));

        Assert.NotEqual(asScope, asResource);
    }

    [Fact]
    public void ForToken_ScopesInDifferentOrder_ProduceSameKey()
    {
        var ascending = TokenCacheKeys.ForToken(Parameters(scopes: ["a", "b"]));
        var descending = TokenCacheKeys.ForToken(Parameters(scopes: ["b", "a"]));

        Assert.Equal(ascending, descending);
    }

    [Fact]
    public void ForToken_UnderTurkishCulture_ProducesSameKeyAsInvariant()
    {
        // Ordering these with the default comparer made the key culture-dependent, so two hosts in
        // different locales cached the same token under different keys.
        var invariant = TokenCacheKeys.ForToken(Parameters(scopes: ["Include", "index", "IZmir"]));

        var original = CultureInfo.CurrentCulture;

        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            Assert.Equal(invariant, TokenCacheKeys.ForToken(Parameters(scopes: ["Include", "index", "IZmir"])));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void ForToken_AbsentAndEmptyScopeLists_ProduceSameKey()
    {
        var absent = TokenCacheKeys.ForToken(Parameters(scopes: null));
        var empty = TokenCacheKeys.ForToken(Parameters(scopes: []));

        Assert.Equal(absent, empty);
    }

    [Fact]
    public void ForToken_AbsentAndEmptyAuthority_ProduceDifferentKeys()
    {
        var absent = TokenCacheKeys.ForToken(Parameters(authority: null));
        var empty = TokenCacheKeys.ForToken(Parameters(authority: string.Empty));

        Assert.NotEqual(absent, empty);
    }

    [Fact]
    public void ForToken_DifferentClients_ProduceDifferentKeys()
    {
        var first = TokenCacheKeys.ForToken(Parameters(clientId: "one"));
        var second = TokenCacheKeys.ForToken(Parameters(clientId: "two"));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ForToken_RotatedSecret_ProducesSameKey()
    {
        // Deliberate: keying on the secret would discard every valid token the moment one rotated,
        // and would write a credential into whatever backs the cache.
        var before = Parameters();
        var after = Parameters();
        after.ClientSecret = "rotated";

        Assert.Equal(TokenCacheKeys.ForToken(before), TokenCacheKeys.ForToken(after));
    }

    [Fact]
    public void ForToken_TokenAndEndpointKeys_ShareNoPrefix()
    {
        var token = TokenCacheKeys.ForToken(Parameters());
        var endpoint = TokenCacheKeys.ForTokenEndpoint("https://idp.example.com");

        Assert.NotEqual(token, endpoint);
        Assert.False(token.StartsWith(endpoint, StringComparison.Ordinal));
        Assert.False(endpoint.StartsWith(token, StringComparison.Ordinal));
    }

    [Fact]
    public void ForTokenEndpoint_DifferentAuthorities_ProduceDifferentKeys()
    {
        Assert.NotEqual(
            TokenCacheKeys.ForTokenEndpoint("https://idp.example.com/a"),
            TokenCacheKeys.ForTokenEndpoint("https://idp.example.com/b"));
    }

    [Fact]
    public void ForToken_WithNullParameters_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => TokenCacheKeys.ForToken(null!));
    }

    [Fact]
    public void ForTokenEndpoint_WithNullAuthority_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => TokenCacheKeys.ForTokenEndpoint(null!));
    }

    [Fact]
    public void ForToken_SubjectTokensDiffering_ProduceDifferentKeys()
    {
        // The reason the subject is in the key at all: two exchanges alike in authority, client,
        // scope and resource but made for different people must not share a cache entry.
        var alice = TokenCacheKeys.ForToken(Parameters(subjectToken: "alice-token"));
        var bob = TokenCacheKeys.ForToken(Parameters(subjectToken: "bob-token"));

        Assert.NotEqual(alice, bob);
    }

    [Fact]
    public void ForToken_SameSubjectToken_ProducesSameKey()
    {
        var first = TokenCacheKeys.ForToken(Parameters(subjectToken: "alice-token"));
        var second = TokenCacheKeys.ForToken(Parameters(subjectToken: "alice-token"));

        Assert.Equal(first, second);
    }

    [Fact]
    public void ForToken_WithAndWithoutSubjectToken_ProduceDifferentKeys()
    {
        // Otherwise a token obtained for somebody would be served to the service acting as itself.
        var onBehalf = TokenCacheKeys.ForToken(Parameters(subjectToken: "alice-token"));
        var asItself = TokenCacheKeys.ForToken(Parameters());

        Assert.NotEqual(onBehalf, asItself);
    }

    [Fact]
    public void ForToken_DoesNotContainTheSubjectToken()
    {
        // A key reaches logs and whatever backs a distributed cache; the bearer token must not.
        var key = TokenCacheKeys.ForToken(Parameters(subjectToken: "alice-token"));

        Assert.DoesNotContain("alice-token", key, StringComparison.Ordinal);
    }

    [Fact]
    public void ForToken_SubjectAndActorTokensWithSameValue_ProduceDifferentKeys()
    {
        // Same value in two different roles is two different requests.
        var asSubject = TokenCacheKeys.ForToken(Parameters(subjectToken: "t"));
        var asActor = TokenCacheKeys.ForToken(Parameters(actorToken: "t"));

        Assert.NotEqual(asSubject, asActor);
    }

    [Fact]
    public void ForToken_AudiencesDifferingOnlyByDelimiter_ProduceDifferentKeys()
    {
        var joined = TokenCacheKeys.ForToken(Parameters(audiences: ["a-b"]));
        var separate = TokenCacheKeys.ForToken(Parameters(audiences: ["a", "b"]));

        Assert.NotEqual(joined, separate);
    }

    [Fact]
    public void ForToken_AudienceAndResourceWithSameValue_ProduceDifferentKeys()
    {
        var audience = TokenCacheKeys.ForToken(Parameters(audiences: ["svc"]));
        var resource = TokenCacheKeys.ForToken(Parameters(resources: ["svc"]));

        Assert.NotEqual(audience, resource);
    }

    [Fact]
    public void ForToken_SubjectTokenTypesDiffering_ProduceDifferentKeys()
    {
        var access = TokenCacheKeys.ForToken(Parameters(subjectToken: "t", subjectTokenType: "urn:a"));
        var id = TokenCacheKeys.ForToken(Parameters(subjectToken: "t", subjectTokenType: "urn:b"));

        Assert.NotEqual(access, id);
    }

    private static TokenRequestParameters Parameters(
        string? authority = "https://idp.example.com",
        string? clientId = "svc",
        IReadOnlyList<string>? scopes = null,
        IReadOnlyList<string>? resources = null,
        IReadOnlyList<string>? audiences = null,
        string? subjectToken = null,
        string? subjectTokenType = null,
        string? actorToken = null)
    {
        return new TokenRequestParameters
        {
            Authority = authority,
            ClientId = clientId,
            ClientSecret = "secret",
            Scopes = scopes,
            Resources = resources,
            Audiences = audiences,
            SubjectToken = subjectToken,
            SubjectTokenType = subjectTokenType,
            ActorToken = actorToken,
        };
    }
}
