using ApricotFramework.Authentication.AspNetCore.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <summary>
/// Checks the settings that govern which inbound tokens are accepted.
/// </summary>
/// <remarks>
/// Registered only when a host validates inbound tokens, so a service that merely calls other services
/// is not asked for an audience it has no use for.
/// <para>
/// Both failures are configurations that could never work: no authority means no signing keys, and
/// audience validation with no audiences rejects every token — silently, until it is checked here.
/// </para>
/// </remarks>
public class ResourceServerOptionsValidator : AuthenticationOptionsValidatorBase, IValidateOptions<ServiceAuthenticationOptions>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ResourceServerOptionsValidator"/> class.
    /// </summary>
    /// <param name="logger">The log to warn on.</param>
    public ResourceServerOptionsValidator(ILogger<ResourceServerOptionsValidator> logger)
        : base(logger)
    {
    }

    /// <inheritdoc />
    public virtual ValidateOptionsResult Validate(string? name, ServiceAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            failures.Add("Authentication:Authority is required to validate inbound tokens.");
        }
        else
        {
            AddAuthorityFailure(failures, "Authentication:Authority", options.Authority, options.AllowInsecure);
        }

        if (options is { ValidateAudience: true, ValidAudiences: null or { Count: 0 } })
        {
            failures.Add(
                "Authentication:ValidAudiences names no audience while audience validation is on, which rejects every token. Name the audiences this service answers for, or set Authentication:ValidateAudience to false.");
        }

        if (options.SkipIssuerValidation && this.ShouldWarn(nameof(options.SkipIssuerValidation)))
        {
            AuthenticationLog.IssuerValidationSkipped(this.Logger, options.Authority);
        }

        if (!options.ValidateTokenType && this.ShouldWarn(nameof(options.ValidateTokenType)))
        {
            AuthenticationLog.TokenTypeCheckDisabled(this.Logger);
        }

        return failures.Count > 0 ? ValidateOptionsResult.Fail(failures) : ValidateOptionsResult.Success;
    }
}
