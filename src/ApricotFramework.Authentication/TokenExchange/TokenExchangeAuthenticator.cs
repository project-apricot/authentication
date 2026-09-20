using ApricotFramework.Authentication.Caching;
using ApricotFramework.Authentication.Hosting;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.TokenExchange;

/// <summary>
/// Gets tokens on behalf of whoever this service is acting for, with the RFC 8693 token exchange
/// grant.
/// </summary>
/// <remarks>
/// <para>
/// The client still authenticates as itself — RFC 8693 requires it, and the credentials are the
/// same ones the client credentials grant would send. What differs is the subject: the token that
/// comes back names the party the <c>subject_token</c> represents, so it carries their authority
/// and not this service's.
/// </para>
/// <para>
/// That is also why a result is cached per subject. The key includes a digest of the subject token
/// for every request that carries one, so two people asking for the same scopes and resource do not
/// share an entry — and neither do two callers waiting on the same in-flight request.
/// </para>
/// <para>
/// Fails rather than falls back. With any subject to act for, there is no exchange to make, and
/// quietly getting a token for the service instead would hand a caller more authority than they
/// arrived with.
/// </para>
/// </remarks>
public class TokenExchangeAuthenticator : TokenEndpointAuthenticator, ITokenExchangeAuthenticator
{
    /// <summary>
    /// The grant type that identifies a token exchange.
    /// </summary>
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>
    /// Where the subject being acted for comes from.
    /// </summary>
    private readonly ISubjectTokenProvider subjectTokenProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenExchangeAuthenticator"/> class.
    /// </summary>
    /// <param name="cache">Where obtained tokens are kept.</param>
    /// <param name="hostingContext">What the process supplies for every request.</param>
    /// <param name="subjectTokenProvider">Where the subject being acted for comes from.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    public TokenExchangeAuthenticator(
        ITokenCache cache,
        ITokenRequestHostingContext hostingContext,
        ISubjectTokenProvider subjectTokenProvider)
        : base(cache, hostingContext)
    {
        ArgumentNullException.ThrowIfNull(subjectTokenProvider);

        this.subjectTokenProvider = subjectTokenProvider;
    }

    /// <inheritdoc />
    protected override string GrantType => TokenExchangeGrantType;

    /// <inheritdoc />
    /// <remarks>
    /// The subject is resolved before anything else, because it is part of what identifies the
    /// token: looking in the cache first would risk answering from an entry belonging to somebody
    /// else. A caller that supplied a subject itself is left alone.
    /// </remarks>
    public override async Task<AccessToken> AuthenticateAsync(
        TokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        if (parameters?.SubjectToken is not null)
        {
            return await base.AuthenticateAsync(parameters, cancellationToken).ConfigureAwait(false);
        }

        var subject = await this.subjectTokenProvider.GetSubjectTokenAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new TokenRequestException(
                TokenRequestFailure.InvalidCredentials,
                "There is no subject to act for, so no token can be exchanged.");

        var enriched = parameters is null ? new TokenRequestParameters() : new TokenRequestParameters(parameters);

        enriched.SubjectToken = subject.Value;
        enriched.SubjectTokenType = subject.TokenType ?? TokenExchangeTokenTypes.AccessToken;

        return await base.AuthenticateAsync(enriched, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override void AppendGrantFields(ICollection<KeyValuePair<string, string>> fields, TokenRequestParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(parameters);

        if (string.IsNullOrWhiteSpace(parameters.SubjectToken))
        {
            throw new TokenRequestException(
                TokenRequestFailure.InvalidCredentials,
                "There is no subject to act for, so no token can be exchanged.");
        }

        fields.Add(new KeyValuePair<string, string>("subject_token", parameters.SubjectToken));
        fields.Add(new KeyValuePair<string, string>("subject_token_type", parameters.SubjectTokenType ?? TokenExchangeTokenTypes.AccessToken));

        if (!string.IsNullOrWhiteSpace(parameters.ActorToken))
        {
            fields.Add(new KeyValuePair<string, string>("actor_token", parameters.ActorToken));

            // Required whenever an actor token is present, per RFC 8693 section 2.1.
            fields.Add(new KeyValuePair<string, string>("actor_token_type", parameters.ActorTokenType ?? TokenExchangeTokenTypes.AccessToken));
        }

        if (!string.IsNullOrWhiteSpace(parameters.RequestedTokenType))
        {
            fields.Add(new KeyValuePair<string, string>("requested_token_type", parameters.RequestedTokenType));
        }

        // One parameter per audience, as with the resource indicators the base sends.
        foreach (var audience in parameters.Audiences ?? [])
        {
            fields.Add(new KeyValuePair<string, string>("audience", audience));
        }
    }
}
