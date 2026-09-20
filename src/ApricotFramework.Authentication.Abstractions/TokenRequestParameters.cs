namespace ApricotFramework.Authentication;

/// <summary>
/// The inputs to a token endpoint request.
/// </summary>
/// <remarks>
/// <para>
/// Shaped after the request the specifications define rather than after any one grant: the client
/// authentication of RFC 6749 section 2.3, the scope of section 3.3, the resource indicators of
/// RFC 8707, and the exchange parameters of RFC 8693. One type, because on the wire it is one form
/// with optional fields, and because a caller states only what differs from the service default —
/// usually the scopes or resources one particular downstream call needs.
/// </para>
/// <para>
/// Nothing here is grant-specific by construction, so a set can describe a request no grant would
/// make — a subject token alongside a client credentials request, say. The authenticator is what
/// knows which grant it performs and therefore which of these it sends; the rest are ignored.
/// </para>
/// </remarks>
public class TokenRequestParameters
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestParameters"/> class.
    /// </summary>
    public TokenRequestParameters()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestParameters"/> class from another.
    /// </summary>
    /// <param name="other">The set to copy.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="other"/> is null.</exception>
    /// <remarks>
    /// An authenticator filling in what a caller left unset copies rather than mutates: the caller's
    /// object may be reused for another call, and a value written into it would leak between them.
    /// </remarks>
    public TokenRequestParameters(TokenRequestParameters other)
    {
        ArgumentNullException.ThrowIfNull(other);

        this.Authority = other.Authority;
        this.ClientId = other.ClientId;
        this.ClientSecret = other.ClientSecret;
        this.Resources = other.Resources;
        this.Scopes = other.Scopes;
        this.Audiences = other.Audiences;
        this.SubjectToken = other.SubjectToken;
        this.SubjectTokenType = other.SubjectTokenType;
        this.ActorToken = other.ActorToken;
        this.ActorTokenType = other.ActorTokenType;
        this.RequestedTokenType = other.RequestedTokenType;
    }

    /// <summary>
    /// Gets or sets the issuer to get the token from.
    /// </summary>
    /// <remarks>
    /// The base address of the provider, not its token endpoint — that is discovered.
    /// </remarks>
    public string? Authority { get; set; }

    /// <summary>
    /// Gets or sets the client identifier to authenticate as.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the secret that authenticates the client.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the resource indicators the token is requested for (RFC 8707).
    /// </summary>
    /// <remarks>
    /// Sent as one <c>resource</c> parameter each. A provider that does not implement RFC 8707
    /// ignores them, so an unexpectedly broad token is the failure to watch for rather than an error.
    /// </remarks>
    public IReadOnlyList<string>? Resources { get; set; }

    /// <summary>
    /// Gets or sets the scopes to request.
    /// </summary>
    public IReadOnlyList<string>? Scopes { get; set; }

    /// <summary>
    /// Gets or sets the logical names of the services the token is requested for (RFC 8693).
    /// </summary>
    /// <remarks>
    /// The alternative to <see cref="Resources"/>, naming the callee rather than locating it. A
    /// provider may accept either, both, or neither.
    /// </remarks>
    public IReadOnlyList<string>? Audiences { get; set; }

    /// <summary>
    /// Gets or sets the token representing the party the request is made on behalf of (RFC 8693).
    /// </summary>
    /// <remarks>
    /// A credential belonging to somebody else, so it is hashed rather than written into a cache
    /// key, and it is the reason two otherwise identical requests deserve different tokens.
    /// </remarks>
    public string? SubjectToken { get; set; }

    /// <summary>
    /// Gets or sets what kind of token <see cref="SubjectToken"/> is (RFC 8693).
    /// </summary>
    public string? SubjectTokenType { get; set; }

    /// <summary>
    /// Gets or sets the token representing the party doing the acting (RFC 8693).
    /// </summary>
    /// <remarks>
    /// Present when delegation is meant rather than impersonation: the result then names both the
    /// subject and the actor.
    /// </remarks>
    public string? ActorToken { get; set; }

    /// <summary>
    /// Gets or sets what kind of token <see cref="ActorToken"/> is (RFC 8693).
    /// </summary>
    public string? ActorTokenType { get; set; }

    /// <summary>
    /// Gets or sets the kind of token being asked for (RFC 8693).
    /// </summary>
    /// <remarks>
    /// Absent means the provider will decide which for every use here is an access token.
    /// </remarks>
    public string? RequestedTokenType { get; set; }
}
