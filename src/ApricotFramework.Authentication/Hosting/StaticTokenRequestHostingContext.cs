namespace ApricotFramework.Authentication.Hosting;

/// <summary>
/// A hosting context whose answers are fixed when it is built.
/// </summary>
/// <remarks>
/// For a console or worker process with no configuration system to read: hand it a client and, if the
/// defaults do not suit, some options, and an authenticator works with nothing else installed. A host
/// that can reload configuration wants a context of its own instead — the ASP.NET Core package has
/// one.
/// </remarks>
public class StaticTokenRequestHostingContext : ITokenRequestHostingContext
{
    /// <summary>
    /// The client requests are sent with.
    /// </summary>
    private readonly HttpClient httpClient;

    /// <summary>
    /// How the grant is carried out.
    /// </summary>
    private readonly TokenEndpointAuthenticatorOptions options;

    /// <summary>
    /// What a caller leaving a value unset gets instead.
    /// </summary>
    private readonly TokenRequestParameters? defaults;

    /// <summary>
    /// Initializes a new instance of the <see cref="StaticTokenRequestHostingContext"/> class.
    /// </summary>
    /// <param name="httpClient">The client to send requests with.</param>
    /// <param name="options">How to carry out the grant, or null for the defaults.</param>
    /// <param name="defaults">
    /// What a caller leaving a value unset gets instead, or null to require every caller to state
    /// everything.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="httpClient"/> is null.</exception>
    public StaticTokenRequestHostingContext(
        HttpClient httpClient,
        TokenEndpointAuthenticatorOptions? options = null,
        TokenRequestParameters? defaults = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        this.httpClient = httpClient;
        this.options = options ?? new TokenEndpointAuthenticatorOptions();

        // Copied, so that a later change to the caller's object cannot alter a request already
        // under way, or one made an hour from now.
        this.defaults = defaults is null ? null : new TokenRequestParameters(defaults);
    }

    /// <inheritdoc />
    public HttpClient GetHttpClient()
    {
        return this.httpClient;
    }

    /// <inheritdoc />
    public TokenEndpointAuthenticatorOptions GetOptions()
    {
        return this.options;
    }

    /// <inheritdoc />
    public TokenRequestParameters GetEffectiveParameters(TokenRequestParameters? input)
    {
        if (this.defaults is null)
        {
            return input is null ? new TokenRequestParameters() : new TokenRequestParameters(input);
        }

        var effective = input is null ? new TokenRequestParameters() : new TokenRequestParameters(input);

        effective.Authority ??= this.defaults.Authority;
        effective.ClientId ??= this.defaults.ClientId;
        effective.ClientSecret ??= this.defaults.ClientSecret;

        // An empty list from the caller means "none", not "use the default", so only an absent one
        // falls back.
        effective.Scopes ??= this.defaults.Scopes;
        effective.Resources ??= this.defaults.Resources;
        effective.Audiences ??= this.defaults.Audiences;

        return effective;
    }
}
