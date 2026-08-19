using ApricotFramework.Authentication.AspNetCore.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <summary>
/// Checks the settings that govern the calls this service makes to other services.
/// </summary>
/// <remarks>
/// Nothing is required, because a service that only validates inbound tokens configures no client. Once
/// anything under <c>Authentication:Client</c> is set, the rest of what a token request needs is
/// required with it: a half-configured client otherwise fails on the first downstream call instead.
/// </remarks>
public class ClientAuthenticationOptionsValidator : AuthenticationOptionsValidatorBase, IValidateOptions<ServiceAuthenticationOptions>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ClientAuthenticationOptionsValidator"/> class.
    /// </summary>
    /// <param name="logger">The log to warn on.</param>
    public ClientAuthenticationOptionsValidator(ILogger<ClientAuthenticationOptionsValidator> logger)
        : base(logger)
    {
    }

    /// <inheritdoc />
    public virtual ValidateOptionsResult Validate(string? name, ServiceAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();
        var client = options.Client;

        var anythingConfigured = !string.IsNullOrWhiteSpace(client.ClientId)
            || !string.IsNullOrWhiteSpace(client.ClientSecret)
            || !string.IsNullOrWhiteSpace(client.Authority);

        if (anythingConfigured)
        {
            if (string.IsNullOrWhiteSpace(client.ClientId))
            {
                failures.Add("Authentication:Client is configured but names no ClientId.");
            }

            var authority = client.Authority ?? options.Authority;

            if (string.IsNullOrWhiteSpace(authority))
            {
                failures.Add(
                    "Authentication:Client has no authority to obtain tokens from. Set Authentication:Client:Authority, or Authentication:Authority when one provider does both.");
            }
            else
            {
                AddAuthorityFailure(failures, "Authentication:Client:Authority", authority, options.AllowInsecure);
            }
        }

        AddPositiveDurationFailure(failures, "Authentication:Client:RequestTimeout", client.RequestTimeout);
        AddPositiveDurationFailure(failures, "Authentication:Client:MetadataCacheDuration", client.MetadataCacheDuration);

        if (client.TokenExpirySkew < TimeSpan.Zero)
        {
            failures.Add(
                $"Authentication:Client:TokenExpirySkew is {client.TokenExpirySkew}, which would keep serving a token after it expired.");
        }

        // Not a failure, because it is a legitimate development setting; loud, because it is never a
        // legitimate production one.
        if (options.AllowInsecure && this.ShouldWarn(nameof(options.AllowInsecure)))
        {
            AuthenticationLog.InsecureTransportEnabled(this.Logger);
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
