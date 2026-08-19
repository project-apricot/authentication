using System.Globalization;

namespace ApricotFramework.Authentication.Tests;

public class ClientAuthenticationKeysTests
{
    [Fact]
    public void ForToken_ScopesDifferingOnlyByDelimiter_ProduceDifferentKeys()
    {
        // Joining the scopes into one field made these one entry, so a token minted for "a-b" was
        // served to a caller asking for "a" and "b" as well.
        var joined = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["a-b"]));
        var separate = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["a", "b"]));

        Assert.NotEqual(joined, separate);
    }

    [Fact]
    public void ForToken_ClientIdImitatingAScopeField_ProducesDifferentKey()
    {
        // The forgery a length prefix exists to stop: without one, a client id carrying the field
        // delimiter writes its own scope into the key and is served that scope's token.
        var forged = ClientAuthenticationKeys.ForToken(Parameters(clientId: "svc|sapi", scopes: []));
        var genuine = ClientAuthenticationKeys.ForToken(Parameters(clientId: "svc", scopes: ["api"]));

        Assert.NotEqual(forged, genuine);
    }

    [Fact]
    public void ForToken_ScopeImitatingAResourceField_ProducesDifferentKey()
    {
        var forged = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["api|rdb"]));
        var genuine = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["api"], resources: ["db"]));

        Assert.NotEqual(forged, genuine);
    }

    [Fact]
    public void ForToken_ScopeAndResourceWithSameValue_ProduceDifferentKeys()
    {
        var asScope = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["api"]));
        var asResource = ClientAuthenticationKeys.ForToken(Parameters(resources: ["api"]));

        Assert.NotEqual(asScope, asResource);
    }

    [Fact]
    public void ForToken_ScopesInDifferentOrder_ProduceSameKey()
    {
        var ascending = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["a", "b"]));
        var descending = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["b", "a"]));

        Assert.Equal(ascending, descending);
    }

    [Fact]
    public void ForToken_UnderTurkishCulture_ProducesSameKeyAsInvariant()
    {
        // Ordering these with the default comparer made the key culture-dependent, so two hosts in
        // different locales cached the same token under different keys.
        var invariant = ClientAuthenticationKeys.ForToken(Parameters(scopes: ["Include", "index", "IZmir"]));

        var original = CultureInfo.CurrentCulture;

        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            Assert.Equal(invariant, ClientAuthenticationKeys.ForToken(Parameters(scopes: ["Include", "index", "IZmir"])));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void ForToken_AbsentAndEmptyScopeLists_ProduceSameKey()
    {
        var absent = ClientAuthenticationKeys.ForToken(Parameters(scopes: null));
        var empty = ClientAuthenticationKeys.ForToken(Parameters(scopes: []));

        Assert.Equal(absent, empty);
    }

    [Fact]
    public void ForToken_AbsentAndEmptyAuthority_ProduceDifferentKeys()
    {
        var absent = ClientAuthenticationKeys.ForToken(Parameters(authority: null));
        var empty = ClientAuthenticationKeys.ForToken(Parameters(authority: string.Empty));

        Assert.NotEqual(absent, empty);
    }

    [Fact]
    public void ForToken_DifferentClients_ProduceDifferentKeys()
    {
        var first = ClientAuthenticationKeys.ForToken(Parameters(clientId: "one"));
        var second = ClientAuthenticationKeys.ForToken(Parameters(clientId: "two"));

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

        Assert.Equal(ClientAuthenticationKeys.ForToken(before), ClientAuthenticationKeys.ForToken(after));
    }

    [Fact]
    public void ForToken_TokenAndEndpointKeys_ShareNoPrefix()
    {
        var token = ClientAuthenticationKeys.ForToken(Parameters());
        var endpoint = ClientAuthenticationKeys.ForTokenEndpoint("https://idp.example.com");

        Assert.NotEqual(token, endpoint);
        Assert.False(token.StartsWith(endpoint, StringComparison.Ordinal));
        Assert.False(endpoint.StartsWith(token, StringComparison.Ordinal));
    }

    [Fact]
    public void ForTokenEndpoint_DifferentAuthorities_ProduceDifferentKeys()
    {
        Assert.NotEqual(
            ClientAuthenticationKeys.ForTokenEndpoint("https://idp.example.com/a"),
            ClientAuthenticationKeys.ForTokenEndpoint("https://idp.example.com/b"));
    }

    [Fact]
    public void ForToken_WithNullParameters_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ClientAuthenticationKeys.ForToken(null!));
    }

    [Fact]
    public void ForTokenEndpoint_WithNullAuthority_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ClientAuthenticationKeys.ForTokenEndpoint(null!));
    }

    private static ClientAuthenticationParameters Parameters(
        string? authority = "https://idp.example.com",
        string? clientId = "svc",
        IReadOnlyList<string>? scopes = null,
        IReadOnlyList<string>? resources = null)
    {
        return new ClientAuthenticationParameters
        {
            Authority = authority,
            ClientId = clientId,
            ClientSecret = "secret",
            Scopes = scopes,
            Resources = resources,
        };
    }
}
