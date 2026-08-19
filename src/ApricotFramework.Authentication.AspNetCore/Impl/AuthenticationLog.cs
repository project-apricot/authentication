using Microsoft.Extensions.Logging;

namespace ApricotFramework.Authentication.AspNetCore.Impl;

/// <remarks>
/// No token and no secret appear here. Client identifiers and authorities do: they are not credentials,
/// and they are what an operator needs to tell one misconfiguration from another.
/// </remarks>
internal static partial class AuthenticationLog
{
    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Warning,
        Message = "Authentication:AllowInsecure is enabled. Plain HTTP authorities are permitted and "
                  + "TLS certificates are not validated on either the metadata channel or the token "
                  + "request, so the provider's identity is unverified. This must not be a production "
                  + "configuration.")]
    public static partial void InsecureTransportEnabled(ILogger logger);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Warning,
        Message = "Authentication:SkipIssuerValidation is enabled, so a token from any issuer whose "
                  + "signing key {Authority} published is accepted. This must not be a production "
                  + "configuration.")]
    public static partial void IssuerValidationSkipped(ILogger logger, string? authority);

    [LoggerMessage(
        EventId = 3,
        Level = LogLevel.Warning,
        Message = "Authentication:ValidateTokenType is off, so the token type header is not checked and "
                  + "an identity token can be presented as an access token.")]
    public static partial void TokenTypeCheckDisabled(ILogger logger);
}
