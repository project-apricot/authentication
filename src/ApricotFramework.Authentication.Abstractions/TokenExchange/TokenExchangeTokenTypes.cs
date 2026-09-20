namespace ApricotFramework.Authentication.TokenExchange;

/// <summary>
/// The token type identifiers RFC 8693 defines.
/// </summary>
/// <remarks>
/// Used for <see cref="TokenRequestParameters.SubjectTokenType"/> and its siblings. A provider may
/// define its own beyond these; the value is a URI, not an enumeration.
/// </remarks>
public static class TokenExchangeTokenTypes
{
    /// <summary>An OAuth 2.0 access token.</summary>
    public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>An OAuth 2.0 refresh token.</summary>
    public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";

    /// <summary>An OpenID Connect identity token.</summary>
    public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";

    /// <summary>A JSON web token that is not one of the more specific kinds above.</summary>
    public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>A SAML 1.1 assertion.</summary>
    public const string Saml1 = "urn:ietf:params:oauth:token-type:saml1";

    /// <summary>A SAML 2.0 assertion.</summary>
    public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
}
