using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net;
using System.Text.Json.Serialization.Metadata;
using System.Text.Json;
using System.Text;
using ApricotFramework.Authentication.Caching;
using ApricotFramework.Authentication.Hosting;
using ApricotFramework.Authentication.Serialization;

namespace ApricotFramework.Authentication.Impl;

/// <summary>
/// Talks to an OAuth 2.0 token endpoint, discovering where it is and what it answered.
/// </summary>
/// <remarks>
/// <para>
/// Everything here is the same whichever grant is being performed: finding the endpoint, proving
/// who the client is, sending the form, reading a refusal that may not be the JSON the spec asks
/// for, and deciding how long the result is worth keeping. A grant adds only its
/// <see cref="GrantType"/> and whatever fields of its own it sends.
/// </para>
/// <para>
/// Subclassing therefore says which <em>grant</em> is performed and nothing else. Where the request
/// is sent and what this service's own credentials are come from the
/// <see cref="ITokenRequestHostingContext"/> instead, so one class per grant serves a console
/// process and a configured host alike.
/// </para>
/// </remarks>
public abstract class TokenEndpointAuthenticator : CachingTokenAuthenticator
{
    /// <summary>
    /// Where a provider publishes its metadata, relative to the authority.
    /// </summary>
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    /// <summary>
    /// The largest protocol document that will be read.
    /// </summary>
    /// <remarks>
    /// Both documents are a few kilobytes. The cap is what stops a provider that has been substituted,
    /// or has simply broken, from being answered with the whole process memory.
    /// </remarks>
    private const long MaxResponseBytes = 1024 * 1024;

    /// <summary>
    /// The longest lifetime honored from a provider.
    /// </summary>
    private static readonly TimeSpan MaxTokenLifetime = TimeSpan.FromHours(24);

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenEndpointAuthenticator"/> class.
    /// </summary>
    /// <param name="cache">Where obtained tokens are kept.</param>
    /// <param name="hostingContext">What the process supplies for every request.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    protected TokenEndpointAuthenticator(ITokenCache cache, ITokenRequestHostingContext hostingContext)
        : base(cache)
    {
        ArgumentNullException.ThrowIfNull(hostingContext);

        this.HostingContext = hostingContext;
    }

    /// <summary>
    /// Gets what the process supplies for every request.
    /// </summary>
    protected ITokenRequestHostingContext HostingContext { get; }

    /// <summary>
    /// Gets the value sent as <c>grant_type</c>.
    /// </summary>
    /// <remarks>
    /// The one thing every grant must state. Everything else about a grant is optional: a grant
    /// that sends no parameters of its own leaves <see cref="AppendGrantFields"/> alone.
    /// </remarks>
    protected abstract string GrantType { get; }

    /// <summary>
    /// Appends the form fields this grant sends beyond the ones every request carries.
    /// </summary>
    /// <param name="fields">The form being built, already carrying <c>grant_type</c>.</param>
    /// <param name="parameters">The effective parameters, with nothing left to fill in.</param>
    /// <remarks>
    /// Scope, resource, and the client's own credentials are added for every grant and must not be
    /// added again here. <paramref name="parameters"/> can carry fields no grant sends; take only
    /// what this one defines.
    /// </remarks>
    protected virtual void AppendGrantFields(ICollection<KeyValuePair<string, string>> fields, TokenRequestParameters parameters)
    {
    }

    /// <inheritdoc />
    /// <remarks>
    /// Delegated to the hosting context, which is the one place that knows what this process
    /// configured.
    /// </remarks>
    protected override TokenRequestParameters GetEffectiveParameters(TokenRequestParameters? input)
    {
        return this.HostingContext.GetEffectiveParameters(input);
    }

    /// <inheritdoc />
    protected override async Task<AccessToken> GetTokenAndCacheAsync(TokenRequestParameters parameters, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var currentOptions = this.HostingContext.GetOptions();
        var authority = ValidateAuthority(parameters.Authority, currentOptions.AllowInsecureAuthority);

        if (string.IsNullOrWhiteSpace(parameters.ClientId))
        {
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, $"No client identifier is configured for authority '{authority}'.");
        }

        var endpoint = await this.Cache.GetTokenEndpointAsync(parameters.Authority!, cancellationToken).ConfigureAwait(false)
            ?? await this.DiscoverTokenEndpointAsync(authority, parameters.Authority!, currentOptions, cancellationToken).ConfigureAwait(false);

        var payload = await this.RequestTokenAsync(endpoint, parameters, currentOptions, cancellationToken).ConfigureAwait(false);

        var lifetime = ClampLifetime(payload.ExpiresIn);

        var context = new AccessToken
        {
            Value = payload.AccessToken!,
            TokenType = string.IsNullOrWhiteSpace(payload.TokenType) ? AccessToken.DefaultTokenType : payload.TokenType,
            ExpiresAt = lifetime is null ? null : DateTimeOffset.UtcNow.Add(lifetime.Value),
        };

        // Not cached when the provider named no lifetime: guessing one either discards a long-lived
        // token immediately or serves an expired one.
        if (lifetime is { } known && known > currentOptions.TokenExpirySkew)
        {
            await this.Cache
                .SetTokenAsync(parameters, context, DateTimeOffset.UtcNow.Add(known - currentOptions.TokenExpirySkew), cancellationToken)
                .ConfigureAwait(false);
        }

        return context;
    }

    /// <summary>
    /// Checks that an authority can be completely asked for a token.
    /// </summary>
    /// <param name="authority">The configured authority.</param>
    /// <param name="allowInsecure">Whether plain HTTP is permitted.</param>
    /// <returns>The authority as a URL.</returns>
    /// <exception cref="TokenRequestException">Thrown when it cannot be used.</exception>
    private static Uri ValidateAuthority(string? authority, bool allowInsecure)
    {
        if (string.IsNullOrWhiteSpace(authority))
        {
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, "No authority is configured to obtain a token from.");
        }

        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, $"The authority '{authority}' is not an absolute http or https URL.");
        }

        if (!allowInsecure && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, $"The authority '{authority}' is not https. Enable insecure authorities to use it, which is intended for development only.");
        }

        return uri;
    }

    /// <summary>
    /// Bounds a provider's stated lifetime.
    /// </summary>
    /// <param name="expiresIn">The lifetime in seconds, as the provider stated it.</param>
    /// <returns>The lifetime to honor, or null when the provider stated none usable.</returns>
    private static TimeSpan? ClampLifetime(long? expiresIn)
    {
        // A negative or absent lifetime means nothing is cached; an absurd one is capped rather than
        // rejected, since the token itself is still valid and overflowing the arithmetic is not.
        if (expiresIn is null or <= 0)
        {
            return null;
        }

        var seconds = Math.Min(expiresIn.Value, (long)MaxTokenLifetime.TotalSeconds);

        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>
    /// Encodes client credentials for an HTTP Basic header, per RFC 6749 section 2.3.1.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="clientSecret">The secret, which may be absent.</param>
    /// <returns>The base64 credential value.</returns>
    private static string BasicCredentials(string clientId, string? clientSecret)
    {
        // Each half is form-urlencoded before the pair is joined, so a secret containing a colon
        // cannot be read back as the delimiter and split in the wrong place.
        var pair = $"{FormUrlEncode(clientId)}:{FormUrlEncode(clientSecret ?? string.Empty)}";

        return Convert.ToBase64String(Encoding.UTF8.GetBytes(pair));
    }

    /// <summary>
    /// Applies the <c>application/x-www-form-urlencoded</c> encoding to one value.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The encoded value.</returns>
    private static string FormUrlEncode(string value)
    {
        // EscapeDataString is percent-encoding, which differs from form encoding on exactly one
        // character: a space is a plus, not %20.
        return Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal);
    }

    /// <summary>
    /// Decides whether metadata describes the authority asked for it.
    /// </summary>
    /// <param name="authority">The authority asked.</param>
    /// <param name="issuer">The issuer the document claims to be.</param>
    /// <returns>True when they are the same issuer.</returns>
    private static bool IsSameIssuer(Uri authority, string? issuer)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var claimed))
        {
            return false;
        }

        // A trailing slash is the one difference providers genuinely vary on; the path otherwise
        // distinguishes tenants and is compared exactly.
        return IsSameOrigin(authority, claimed)
            && string.Equals(authority.AbsolutePath.TrimEnd('/'), claimed.AbsolutePath.TrimEnd('/'), StringComparison.Ordinal);
    }

    /// <summary>
    /// Decides whether two URLs address the same host.
    /// </summary>
    /// <param name="left">The first URL.</param>
    /// <param name="right">The second URL.</param>
    /// <returns>True when a scheme, host and port all agree.</returns>
    private static bool IsSameOrigin(Uri left, Uri right)
    {
        return string.Equals(left.Scheme, right.Scheme, StringComparison.Ordinal)
            && string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase)
            && left.Port == right.Port;
    }

    /// <summary>
    /// Maps an OAuth error code to what a caller can do about it (RFC 6749 section 5.2).
    /// </summary>
    /// <param name="error">The error code the provider returned.</param>
    /// <returns>The corresponding failure.</returns>
    private static TokenRequestFailure MapProviderError(string error)
    {
        // Ordinal and case-sensitive: these are protocol tokens with one spelling each, and a code in
        // the wrong case is a provider not following the spec rather than a code to recognize.
        return error switch
        {
            "invalid_client" or "unauthorized_client" or "invalid_grant" =>
                TokenRequestFailure.InvalidCredentials,
            "invalid_scope" => TokenRequestFailure.InvalidScope,
            "invalid_request" or "unsupported_grant_type" =>
                TokenRequestFailure.InvalidConfiguration,
            "server_error" or "temporarily_unavailable" => TokenRequestFailure.Unavailable,
            _ => TokenRequestFailure.Unknown,
        };
    }

    /// <summary>
    /// Maps a token endpoint's status code to a failure, for a response that carried no error code.
    /// </summary>
    /// <param name="status">The status code returned.</param>
    /// <returns>The corresponding failure.</returns>
    private static TokenRequestFailure MapStatusCode(HttpStatusCode status)
    {
        return status switch
        {
            HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden =>
                TokenRequestFailure.InvalidCredentials,
            >= HttpStatusCode.InternalServerError or HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests =>
                TokenRequestFailure.Unavailable,
            _ => TokenRequestFailure.Unknown,
        };
    }

    /// <summary>
    /// Reads a provider's metadata and caches the endpoint it names.
    /// </summary>
    /// <param name="authority">The validated authority.</param>
    /// <param name="authorityKey">The authority exactly as configured, which is what the cache keys on.</param>
    /// <param name="currentOptions">How the grant is carried out.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The token endpoint to request from.</returns>
    /// <exception cref="TokenRequestException">Thrown when the metadata cannot be trusted.</exception>
    private async Task<string> DiscoverTokenEndpointAsync(
        Uri authority,
        string authorityKey,
        TokenEndpointAuthenticatorOptions currentOptions,
        CancellationToken cancellationToken)
    {
        var metadataUrl = new Uri(authority.GetLeftPart(UriPartial.Path).TrimEnd('/') + DiscoveryPath);

        using var request = new HttpRequestMessage(HttpMethod.Get, metadataUrl);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await this.SendAsync(request, authority, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new TokenRequestException(MapStatusCode(response.StatusCode), $"The metadata for authority '{authority}' could not be read: the provider answered {(int)response.StatusCode}.");
        }

        var metadata = await ReadJsonAsync(response, AuthenticationJson.Default.OpenIdProviderMetadata, authority, cancellationToken).ConfigureAwait(false);

        if (metadata is null || !IsSameIssuer(authority, metadata.Issuer))
        {
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, $"The metadata at '{metadataUrl}' describes issuer '{metadata?.Issuer}' rather than the authority it was read from.");
        }

        if (!Uri.TryCreate(metadata.TokenEndpoint, UriKind.Absolute, out var endpoint) || !IsSameOrigin(authority, endpoint))
        {
            // A document that names an endpoint elsewhere is how a substituted or tampered response
            // collects the client secret, so it is refused rather than followed.
            throw new TokenRequestException(TokenRequestFailure.InvalidConfiguration, $"The metadata for authority '{authority}' names token endpoint '{metadata.TokenEndpoint}', which is not on the same host.");
        }

        await this.Cache.SetTokenEndpointAsync(
            authorityKey,
            endpoint.AbsoluteUri,
            DateTimeOffset.UtcNow.Add(currentOptions.MetadataCacheDuration),
            cancellationToken).ConfigureAwait(false);

        return endpoint.AbsoluteUri;
    }

    /// <summary>
    /// Requests a token and reads the answer.
    /// </summary>
    /// <param name="endpoint">The token endpoint to request from.</param>
    /// <param name="parameters">The effective parameters.</param>
    /// <param name="currentOptions">How the grant is carried out.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The provider's answer, known to carry a token.</returns>
    /// <exception cref="TokenRequestException">Thrown when no token was issued.</exception>
    private async Task<TokenEndpointResponse> RequestTokenAsync(
        string endpoint,
        TokenRequestParameters parameters,
        TokenEndpointAuthenticatorOptions currentOptions,
        CancellationToken cancellationToken)
    {
        var authority = new Uri(endpoint);

        var fields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", this.GrantType),
        };

        this.AppendGrantFields(fields, parameters);

        var scopes = parameters.Scopes ?? [];

        if (scopes.Count > 0)
        {
            fields.Add(new KeyValuePair<string, string>("scope", string.Join(' ', scopes)));
        }

        // One parameter per resource, per RFC 8707, rather than a joined list.
        foreach (var resource in parameters.Resources ?? [])
        {
            fields.Add(new KeyValuePair<string, string>("resource", resource));
        }

        if (currentOptions.CredentialStyle == ClientCredentialStyle.PostBody)
        {
            fields.Add(new KeyValuePair<string, string>("client_id", parameters.ClientId!));
            fields.Add(new KeyValuePair<string, string>("client_secret", parameters.ClientSecret ?? string.Empty));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);

        // Assigned after the using takes hold, so a failure building the body still disposes the request.
        request.Content = new FormUrlEncodedContent(fields);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (currentOptions.CredentialStyle == ClientCredentialStyle.Basic)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                BasicCredentials(parameters.ClientId!, parameters.ClientSecret));
        }

        using var response = await this.SendAsync(request, authority, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            // Read leniently, because a failure is frequently not the JSON the spec asks for — a proxy
            // in front of the provider answers 502 with HTML — and the status classifies it regardless.
            var refusal = await TryReadJsonAsync(response, AuthenticationJson.Default.TokenEndpointResponse, cancellationToken).ConfigureAwait(false);

            // The error code, never the description: providers echo the request into it, and a request
            // to a token endpoint carries a secret.
            throw refusal?.Error is { Length: > 0 } code
                ? new TokenRequestException(
                    MapProviderError(code),
                    $"The provider at '{authority}' refused client '{parameters.ClientId}': {code}.")
                : new TokenRequestException(
                    MapStatusCode(response.StatusCode),
                    $"The provider at '{authority}' answered {(int)response.StatusCode} for client '{parameters.ClientId}'.");
        }

        var payload = await ReadJsonAsync(response, AuthenticationJson.Default.TokenEndpointResponse, authority, cancellationToken).ConfigureAwait(false);

        // Providers exist that report a refusal with 200, so the code is honored either way.
        if (payload?.Error is { Length: > 0 } error)
        {
            throw new TokenRequestException(
                MapProviderError(error),
                $"The provider at '{authority}' refused client '{parameters.ClientId}': {error}.");
        }

        if (payload is null || string.IsNullOrWhiteSpace(payload.AccessToken))
        {
            throw new TokenRequestException(
                TokenRequestFailure.Unknown,
                $"The provider at '{authority}' answered successfully but issued no token for client '{parameters.ClientId}'.");
        }

        return payload;
    }

    /// <summary>
    /// Sends a request, reporting a transport failure as something that may recover.
    /// </summary>
    /// <param name="request">The request to send.</param>
    /// <param name="authority">The authority being addressed, for the message.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The response.</returns>
    /// <exception cref="TokenRequestException">Thrown when the provider could not be reached.</exception>
    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        Uri authority,
        CancellationToken cancellationToken)
    {
        try
        {
            return await this.HostingContext.GetHttpClient()
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new TokenRequestException(
                TokenRequestFailure.Unavailable,
                $"The provider at '{authority}' could not be reached.",
                exception);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            // A cancellation nobody asked for is the client's timeout, which is the provider being
            // slow rather than the caller giving up.
            throw new TokenRequestException(
                TokenRequestFailure.Unavailable,
                $"The provider at '{authority}' did not answer in time.",
                exception);
        }
    }

    /// <summary>
    /// Reads a bounded JSON document from a response that already counts as a failure.
    /// </summary>
    /// <typeparam name="T">The document type.</typeparam>
    /// <param name="response">The response to read.</param>
    /// <param name="typeInfo">The generated reader for the document.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The document, or null when the body was not the expected JSON.</returns>
    private static async Task<T?> TryReadJsonAsync<T>(
        HttpResponseMessage response,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
        where T : class
    {
        try
        {
            await response.Content.LoadIntoBufferAsync(MaxResponseBytes, cancellationToken).ConfigureAwait(false);

            return await response.Content.ReadFromJsonAsync(typeInfo, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or HttpRequestException)
        {
            // The status code is the answer here, so an unreadable body is not worth failing over.
            return null;
        }
    }

    /// <summary>
    /// Reads a bounded JSON document from a response.
    /// </summary>
    /// <typeparam name="T">The document type.</typeparam>
    /// <param name="response">The response to read.</param>
    /// <param name="typeInfo">The generated reader for the document.</param>
    /// <param name="authority">The authority being addressed, for the message.</param>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The document, or null when the body was empty.</returns>
    /// <exception cref="TokenRequestException">Thrown when the body could not be read.</exception>
    private static async Task<T?> ReadJsonAsync<T>(
        HttpResponseMessage response,
        JsonTypeInfo<T> typeInfo,
        Uri authority,
        CancellationToken cancellationToken)
        where T : class
    {
        try
        {
            await response.Content.LoadIntoBufferAsync(MaxResponseBytes, cancellationToken).ConfigureAwait(false);

            return await response.Content.ReadFromJsonAsync(typeInfo, cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new TokenRequestException(
                TokenRequestFailure.Unknown,
                $"The provider at '{authority}' answered with something other than the expected JSON.",
                exception);
        }
        catch (HttpRequestException exception)
        {
            throw new TokenRequestException(
                TokenRequestFailure.Unavailable,
                $"The answer from the provider at '{authority}' could not be read, or exceeded {MaxResponseBytes} bytes.",
                exception);
        }
        catch (NotSupportedException exception)
        {
            // What ReadFromJsonAsync reports for a content type it will not parse, such as the HTML
            // error page a proxy in front of the provider answers with.
            throw new TokenRequestException(
                TokenRequestFailure.Unknown,
                $"The provider at '{authority}' answered with an unexpected content type.",
                exception);
        }
    }
}
