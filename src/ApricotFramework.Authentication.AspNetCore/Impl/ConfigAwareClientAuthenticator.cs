using ApricotFramework.Authentication.AspNetCore.Options;
using ApricotFramework.Authentication.Impl;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <summary>
/// The client credentials authenticator, with everything a caller left unset taken from configuration.
/// </summary>
/// <remarks>
/// Reads the options on each call rather than capturing them, so a configuration reload takes effect
/// without a restart. The client comes from the factory for the same reason: a captured
/// <see cref="HttpClient"/> in a singleton never rotates its handler.
/// </remarks>
public class ConfigAwareClientAuthenticator : ClientCredentialsAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConfigAwareClientAuthenticator"/> class.
    /// </summary>
    /// <param name="options">The live settings.</param>
    /// <param name="httpClientFactory">Where the client for each request comes from.</param>
    /// <param name="cache">Where obtained tokens are kept.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    public ConfigAwareClientAuthenticator(
        IOptionsMonitor<ServiceAuthenticationOptions> options,
        IHttpClientFactory httpClientFactory,
        IClientAuthenticationCache cache)
        : base(cache)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        this.Options = options;
        this.HttpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Gets the live settings.
    /// </summary>
    protected IOptionsMonitor<ServiceAuthenticationOptions> Options { get; }

    /// <summary>
    /// Gets where the client for each request comes from.
    /// </summary>
    protected IHttpClientFactory HttpClientFactory { get; }

    /// <inheritdoc />
    protected override HttpClient GetHttpClient()
    {
        return this.HttpClientFactory.CreateClient(AuthenticationHttpClients.Token);
    }

    /// <inheritdoc />
    protected override ClientCredentialsAuthenticatorOptions GetOptions()
    {
        var current = this.Options.CurrentValue;

        return new ClientCredentialsAuthenticatorOptions
        {
            CredentialStyle = current.Client.CredentialStyle,
            TokenExpirySkew = current.Client.TokenExpirySkew,
            MetadataCacheDuration = current.Client.MetadataCacheDuration,
            AllowInsecureAuthority = current.AllowInsecure,
        };
    }

    /// <inheritdoc />
    protected override ClientAuthenticationParameters GetEffectiveParameters(ClientAuthenticationParameters? input)
    {
        var current = this.Options.CurrentValue;

        return new ClientAuthenticationParameters
        {
            // The client's own authority wins over the inbound one, which is only a fallback for the
            // common case of one provider doing both jobs.
            Authority = input?.Authority ?? current.Client.Authority ?? current.Authority,
            ClientId = input?.ClientId ?? current.Client.ClientId,
            ClientSecret = input?.ClientSecret ?? current.Client.ClientSecret,

            // An empty list from the caller means "no scopes", not "use the configured ones", so only
            // an absent one falls back.
            Scopes = input?.Scopes ?? AsList(current.Client.Scopes),
            Resources = input?.Resources ?? AsList(current.Client.Resources),
        };
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
