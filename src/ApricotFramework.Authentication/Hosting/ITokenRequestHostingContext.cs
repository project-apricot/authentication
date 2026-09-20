namespace ApricotFramework.Authentication.Hosting;

/// <summary>
/// What the process an authenticator runs in supplies for every token request it makes.
/// </summary>
/// <remarks>
/// <para>
/// The environment axis, kept out of the inheritance chain on purpose. A subclass of
/// <see cref="Impl.TokenEndpointAuthenticator"/> says which <em>grant</em> it performs and nothing
/// else; how the request is sent, and what this service's own credentials are, come from here. The
/// two used to be one chain, which meant a config-aware variant of every grant, each holding the same
/// three members.
/// </para>
/// <para>
/// Asked on every request rather than captured, so a context over live configuration reflects a
/// change without a restart, and one over a client factory returns a client whose handler still
/// rotates.
/// </para>
/// </remarks>
public interface ITokenRequestHostingContext
{
    /// <summary>
    /// Gets the client to send this request with.
    /// </summary>
    /// <returns>The client to use.</returns>
    /// <remarks>
    /// A method rather than a property because an implementation over a client factory returns a
    /// different instance each time, which is how handler rotation keeps working.
    /// </remarks>
    HttpClient GetHttpClient();

    /// <summary>
    /// Gets how the grant is carried out for this request.
    /// </summary>
    /// <returns>The options to use.</returns>
    TokenEndpointAuthenticatorOptions GetOptions();

    /// <summary>
    /// Fills in from this process's own settings whatever the caller left unset.
    /// </summary>
    /// <param name="input">What the caller asked for which may be absent entirely.</param>
    /// <returns>The parameters to get a token with.</returns>
    /// <remarks>
    /// Copy rather than mutate: the caller's object may be reused for another call, and a default
    /// written into it would then apply where it was never asked for. Copying also carries through
    /// what a grant filled in before this ran — the subject of an exchange, say — which building a
    /// fresh set would silently drop.
    /// </remarks>
    TokenRequestParameters GetEffectiveParameters(TokenRequestParameters? input);
}
