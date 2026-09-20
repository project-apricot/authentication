using ApricotFramework.Authentication.Caching;
using ApricotFramework.Authentication.Hosting;
using ApricotFramework.Authentication.Impl;

namespace ApricotFramework.Authentication.ClientCredentials;

/// <summary>
/// Gets tokens with the OAuth 2.0 client credentials grant.
/// </summary>
/// <remarks>
/// The service asking is the subject: there is nobody else involved, so the grant sends nothing
/// beyond what every token request carries, and the client's own credentials are the whole of its
/// claim. <see cref="TokenEndpointAuthenticator"/> does the rest, and the hosting context says where
/// those credentials come from — so this one class serves a console process and a configured host
/// alike.
/// </remarks>
public class ClientCredentialsAuthenticator : TokenEndpointAuthenticator, IClientCredentialsAuthenticator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientCredentialsAuthenticator"/> class.
    /// </summary>
    /// <param name="cache">Where obtained tokens are kept.</param>
    /// <param name="hostingContext">What the process supplies for every request.</param>
    /// <exception cref="ArgumentNullException">Thrown when any argument is null.</exception>
    public ClientCredentialsAuthenticator(ITokenCache cache, ITokenRequestHostingContext hostingContext)
        : base(cache, hostingContext)
    {
    }

    /// <inheritdoc />
    protected override string GrantType => "client_credentials";
}
