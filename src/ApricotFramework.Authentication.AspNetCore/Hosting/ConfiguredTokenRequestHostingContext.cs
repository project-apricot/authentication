using ApricotFramework.Authentication.AspNetCore.Options;
using ApricotFramework.Authentication.Hosting;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Hosting;

/// <summary>
/// A hosting context that answers from the <c>Authentication</c> section as it stands right now.
/// </summary>
/// <remarks>
/// <para>
/// One context serves every grant. This service is who it is whether it asks for a token of its own
/// or one on somebody's behalf, so the credentials under <c>Authentication:Client</c> are the same
/// either way; what differs is the grant, which is the authenticator's business and not this one's.
/// </para>
/// <para>
/// Nothing is captured. The settings are read on each call so a configuration reload takes effect
/// without a restart, and the client comes from the factory for the same reason: a captured
/// <see cref="HttpClient"/> in a singleton never rotates its handler.
/// </para>
/// </remarks>
public class ConfiguredTokenRequestHostingContext : ITokenRequestHostingContext
{
    /// <summary>
    /// The live settings.
    /// </summary>
    private readonly IOptionsMonitor<ServiceAuthenticationOptions> options;

    /// <summary>
    /// Where the client for each request comes from.
    /// </summary>
    private readonly IHttpClientFactory httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConfiguredTokenRequestHostingContext"/> class.
    /// </summary>
    /// <param name="options">The live settings.</param>
    /// <param name="httpClientFactory">Where the client for each request comes from.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    public ConfiguredTokenRequestHostingContext(
        IOptionsMonitor<ServiceAuthenticationOptions> options,
        IHttpClientFactory httpClientFactory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        this.options = options;
        this.httpClientFactory = httpClientFactory;
    }

    /// <inheritdoc />
    public HttpClient GetHttpClient()
    {
        return this.httpClientFactory.CreateClient(AuthenticationHttpClients.Token);
    }

    /// <inheritdoc />
    public TokenEndpointAuthenticatorOptions GetOptions()
    {
        var current = this.options.CurrentValue;

        return new TokenEndpointAuthenticatorOptions
        {
            CredentialStyle = current.Client.CredentialStyle,
            TokenExpirySkew = current.Client.TokenExpirySkew,
            MetadataCacheDuration = current.Client.MetadataCacheDuration,
            AllowInsecureAuthority = current.AllowInsecure
        };
    }

    /// <inheritdoc />
    public TokenRequestParameters GetEffectiveParameters(TokenRequestParameters? input)
    {
        var current = this.options.CurrentValue;
        var effective = input is null ? new TokenRequestParameters() : new TokenRequestParameters(input);

        // The client's own authority wins over the inbound one, which is only a fallback for the
        // common case of one provider doing both jobs.
        effective.Authority ??= current.Client.Authority ?? current.Authority;
        effective.ClientId ??= current.Client.ClientId;
        effective.ClientSecret ??= current.Client.ClientSecret;

        // An empty list from the caller means "no scopes", not "use the configured ones", so only an
        // absent one falls back.
        effective.Scopes ??= AsList(current.Client.Scopes);
        effective.Resources ??= AsList(current.Client.Resources);

        return effective;
    }

    /// <summary>
    /// Snapshots a configured list, so a later reload cannot change a request already under way.
    /// </summary>
    /// <param name="values">The configured values.</param>
    /// <returns>A copy, or an empty list.</returns>
    private static IReadOnlyList<string> AsList(IList<string>? values)
    {
        return values is null ? [] : [.. values];
    }
}
