namespace ApricotFramework.Authentication.ErrorDefinitions;

/// <summary>
/// The codes this library reports authentication failures under.
/// </summary>
/// <remarks>
/// Three, because that is how many outcomes a client acts on differently: it was not identified, a
/// dependency of ours is down, or a deployment of ours is wrong. The specific reason travels in the
/// payload, so the set a client needs text for does not grow with every new way to fail.
/// </remarks>
public static class AuthenticationErrors
{
    /// <summary>
    /// The request carried no identified caller. Reported as not authenticated.
    /// </summary>
    public const string NoPrincipal = "AUTH_NO_PRINCIPAL";

    /// <summary>
    /// A token for an onward call could not be obtained, and waiting may help. Reported as unavailable.
    /// </summary>
    public const string ClientTokenUnavailable = "AUTH_CLIENT_TOKEN_UNAVAILABLE";

    /// <summary>
    /// A token for an onward call could not be obtained, and waiting will not help. Reported as internal.
    /// </summary>
    /// <remarks>
    /// Deliberately not <c>not_authenticated</c>. The caller presented a perfectly good credential; it
    /// is this service that cannot present one of its own, and telling the caller to authenticate again
    /// is both useless and a lie about whose fault it is.
    /// </remarks>
    public const string ClientMisconfigured = "AUTH_CLIENT_MISCONFIGURED";
}
