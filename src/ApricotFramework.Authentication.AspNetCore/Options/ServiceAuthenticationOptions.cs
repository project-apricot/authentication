namespace ApricotFramework.Authentication.AspNetCore.Options;

/// <summary>
/// How this service authenticates, bound from the <c>Authentication</c> section.
/// </summary>
/// <remarks>
/// Covers both directions: the tokens the service accepts, and under <see cref="Client"/> the
/// credentials it presents to other services. Not named <c>AuthenticationOptions</c>, which already
/// means something else in ASP.NET Core and would leave consumers disambiguating the two.
/// </remarks>
public class ServiceAuthenticationOptions
{
    /// <summary>
    /// The configuration section these options bind from.
    /// </summary>
    public const string SectionName = "Authentication";

    /// <summary>
    /// The token types accepted when the configuration names none.
    /// </summary>
    /// <remarks>
    /// <c>at+jwt</c> is what RFC 9068 defines and what IdentityServer emits. Azure AD, Auth0 and
    /// Keycloak emit no <c>typ</c> at all, so those need this set explicitly — to their own value, or
    /// to an empty list to accept any.
    /// </remarks>
    public static readonly IReadOnlyList<string> DefaultValidTokenTypes = ["at+jwt"];

    /// <summary>
    /// Gets or sets the issuer whose tokens are accepted.
    /// </summary>
    /// <remarks>
    /// Also where signing keys are read from, so it has to be reachable from the service at startup.
    /// </remarks>
    public string? Authority { get; set; }

    /// <summary>
    /// Gets or sets the audiences a token may be addressed to.
    /// </summary>
    /// <remarks>
    /// Required unless <see cref="ValidateAudience"/> is turned off. Leaving it empty while audience
    /// validation is on rejects every token, so it fails at startup instead.
    /// </remarks>
    public IList<string>? ValidAudiences { get; set; }

    /// <summary>
    /// Gets or sets the issuers accepted, when more than <see cref="Authority"/> alone.
    /// </summary>
    /// <remarks>
    /// Unset accepts the authority. Needed where the issuer in a token differs from the URL the service
    /// reaches the provider on, which happens behind an ingress that rewrites the host.
    /// </remarks>
    public IList<string>? ValidIssuers { get; set; }

    /// <summary>
    /// Gets or sets the <c>typ</c> header values accepted.
    /// </summary>
    /// <remarks>
    /// Unset means <see cref="DefaultValidTokenTypes"/>. Configuring it replaces that default rather
    /// than adding to it. To accept any type, turn <see cref="ValidateTokenType"/> off — an empty list
    /// here cannot express it, because the configuration binder reads an empty array as nothing at all.
    /// </remarks>
    public IList<string>? ValidTokenTypes { get; set; }

    /// <summary>
    /// Gets or sets whether a token's audience is checked.
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Gets or sets whether a token's <c>typ</c> header is checked.
    /// </summary>
    /// <remarks>
    /// The check is what stops an identity token being presented as an access token, so turning it off
    /// is deliberate. Providers that emit no <c>typ</c> at all need it off, or need
    /// <see cref="ValidTokenTypes"/> set to whatever they do emit.
    /// </remarks>
    public bool ValidateTokenType { get; set; } = true;

    /// <summary>
    /// Gets or sets whether a token's issuer goes unchecked.
    /// </summary>
    /// <remarks>
    /// For development against a provider reachable under more than one name. It accepts a token from
    /// any issuer whose signing key the authority published, so it is not a production setting.
    /// </remarks>
    public bool SkipIssuerValidation { get; set; }

    /// <summary>
    /// Gets or sets whether plain HTTP and untrusted certificates are accepted.
    /// </summary>
    /// <remarks>
    /// Development only, and warned about at startup when on. It permits an <c>http</c> authority and
    /// disables certificate validation on both the inbound metadata channel and the outbound token
    /// request, so nothing about the provider's identity is verified.
    /// </remarks>
    public bool AllowInsecure { get; set; }

    /// <summary>
    /// Gets or sets the claim holding the principal's display name.
    /// </summary>
    /// <remarks>
    /// Set this and <see cref="RoleClaimType"/> for a provider that names them unconventionally;
    /// otherwise <c>[Authorize(Roles = ...)]</c> matches nothing and reports it as a plain 403.
    /// </remarks>
    public string? NameClaimType { get; set; }

    /// <summary>
    /// Gets or sets the claim holding the principal's roles.
    /// </summary>
    public string? RoleClaimType { get; set; }

    /// <summary>
    /// Gets or sets how much clock difference between this service and the provider is tolerated.
    /// </summary>
    /// <remarks>
    /// Unset leaves the framework default of five minutes, which is generous where clocks are
    /// synchronised.
    /// </remarks>
    public TimeSpan? ClockSkew { get; set; }

    /// <summary>
    /// Gets or sets the credentials this service calls other services with.
    /// </summary>
    public ClientAuthenticationOptions Client { get; set; } = new();
}
