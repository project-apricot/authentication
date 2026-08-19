using Microsoft.Extensions.Logging;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <summary>
/// What the settings checks share: a warning that fires once, and the two rules more than one setting
/// is held to.
/// </summary>
/// <remarks>
/// The checks are two independent validators rather than one, so a service doing both jobs registers
/// both and still has each problem reported once.
/// </remarks>
public abstract class AuthenticationOptionsValidatorBase
{
    /// <summary>
    /// The warnings already emitted, since options are validated more than once per start.
    /// </summary>
    private readonly HashSet<string> warned = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticationOptionsValidatorBase"/> class.
    /// </summary>
    /// <param name="logger">The log to warn on.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="logger"/> is null.</exception>
    protected AuthenticationOptionsValidatorBase(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        this.Logger = logger;
    }

    /// <summary>
    /// Gets the log to warn on.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Records a failure when an authority cannot be reached as configured.
    /// </summary>
    /// <param name="failures">The failures collected so far.</param>
    /// <param name="settingName">The setting being checked, for the message.</param>
    /// <param name="authority">The configured authority.</param>
    /// <param name="allowInsecure">Whether plain HTTP is permitted.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="failures"/> is null.</exception>
    protected static void AddAuthorityFailure(
        List<string> failures,
        string settingName,
        string authority,
        bool allowInsecure)
    {
        ArgumentNullException.ThrowIfNull(failures);

        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            failures.Add($"{settingName} '{authority}' is not an absolute http or https URL.");

            return;
        }

        if (!allowInsecure && uri.Scheme != Uri.UriSchemeHttps)
        {
            failures.Add(
                $"{settingName} '{authority}' is not https. Set Authentication:AllowInsecure to use it, which is intended for development only.");
        }
    }

    /// <summary>
    /// Records a failure when a duration that has to elapse is zero or negative.
    /// </summary>
    /// <param name="failures">The failures collected so far.</param>
    /// <param name="settingName">The setting being checked, for the message.</param>
    /// <param name="value">The configured duration.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="failures"/> is null.</exception>
    protected static void AddPositiveDurationFailure(List<string> failures, string settingName, TimeSpan value)
    {
        ArgumentNullException.ThrowIfNull(failures);

        if (value <= TimeSpan.Zero)
        {
            failures.Add($"{settingName} is {value}, which would abandon every attempt before it started.");
        }
    }

    /// <summary>
    /// Decides whether a warning still needs emitting.
    /// </summary>
    /// <param name="key">The warning in question.</param>
    /// <returns>True the first time it is seen, false afterward.</returns>
    /// <remarks>
    /// Options are validated once at startup and again when something first resolves them, so warning
    /// without this guard prints every message twice and makes the log look broken.
    /// </remarks>
    protected virtual bool ShouldWarn(string key)
    {
        lock (this.warned)
        {
            return this.warned.Add(key);
        }
    }
}
