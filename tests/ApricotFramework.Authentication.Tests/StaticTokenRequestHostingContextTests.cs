using ApricotFramework.Authentication.Hosting;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// Covers the context a host-free process uses, and in particular that filling in a default never
/// overwrites something the caller meant.
/// </summary>
public class StaticTokenRequestHostingContextTests
{
    [Fact]
    public void GetEffectiveParameters_WithNoDefaults_ReturnsWhatTheCallerAskedFor()
    {
        var context = Context();

        var effective = context.GetEffectiveParameters(new TokenRequestParameters { ClientId = "svc" });

        Assert.Equal("svc", effective.ClientId);
        Assert.Null(effective.Authority);
    }

    [Fact]
    public void GetEffectiveParameters_WithNoInput_StillReturnsASet()
    {
        Assert.NotNull(Context().GetEffectiveParameters(null));
    }

    [Fact]
    public void GetEffectiveParameters_FillsOnlyWhatTheCallerLeftUnset()
    {
        var context = Context(new TokenRequestParameters { Authority = "https://idp.example.com", ClientId = "default" });

        var effective = context.GetEffectiveParameters(new TokenRequestParameters { ClientId = "caller" });

        Assert.Equal("https://idp.example.com", effective.Authority);
        Assert.Equal("caller", effective.ClientId);
    }

    [Fact]
    public void GetEffectiveParameters_TreatsAnEmptyListAsAnAnswerRatherThanAnAbsence()
    {
        // "No scopes" and "you choose" are different requests, and a provider answers them
        // differently.
        var context = Context(new TokenRequestParameters { Scopes = ["configured"] });

        var effective = context.GetEffectiveParameters(new TokenRequestParameters { Scopes = [] });

        Assert.Empty(effective.Scopes!);
    }

    [Fact]
    public void GetEffectiveParameters_DoesNotWriteIntoTheCallersObject()
    {
        // The caller may reuse it for another call, where the default was never asked for.
        var context = Context(new TokenRequestParameters { ClientId = "default" });
        var input = new TokenRequestParameters();

        context.GetEffectiveParameters(input);

        Assert.Null(input.ClientId);
    }

    [Fact]
    public void GetEffectiveParameters_CarriesThroughWhatAGrantAlreadyFilledIn()
    {
        // The exchange resolves its subject before this runs, and rebuilding the set would drop it.
        var context = Context(new TokenRequestParameters { ClientId = "default" });

        var effective = context.GetEffectiveParameters(new TokenRequestParameters { SubjectToken = "inbound" });

        Assert.Equal("inbound", effective.SubjectToken);
        Assert.Equal("default", effective.ClientId);
    }

    [Fact]
    public void Constructor_CopiesTheDefaults_SoALaterChangeCannotAlterARequest()
    {
        var defaults = new TokenRequestParameters { ClientId = "at-construction" };
        var context = Context(defaults);

        defaults.ClientId = "changed-afterwards";

        Assert.Equal("at-construction", context.GetEffectiveParameters(null).ClientId);
    }

    [Fact]
    public void Constructor_WithNoHttpClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new StaticTokenRequestHostingContext(null!));
    }

    [Fact]
    public void GetOptions_WithNoneGiven_AnswersTheDefaults()
    {
        Assert.Equal(new TokenEndpointAuthenticatorOptions().TokenExpirySkew, Context().GetOptions().TokenExpirySkew);
    }

    [Fact]
    public void GetHttpClient_AnswersTheOneItWasBuiltWith()
    {
        using var httpClient = new HttpClient();
        var context = new StaticTokenRequestHostingContext(httpClient);

        Assert.Same(httpClient, context.GetHttpClient());
    }

    private static StaticTokenRequestHostingContext Context(TokenRequestParameters? defaults = null)
    {
        return new StaticTokenRequestHostingContext(new HttpClient(), defaults: defaults);
    }
}
