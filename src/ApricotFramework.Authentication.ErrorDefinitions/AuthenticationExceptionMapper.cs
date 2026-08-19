using ApricotFramework.Authentication.AspNetCore.Exceptions;
using ApricotFramework.ErrorDefinitions;
using ApricotFramework.ErrorDefinitions.AspNetCore;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.ErrorDefinitions;

/// <summary>
/// Classifies authentication failures, keeping whose fault each one is.
/// </summary>
/// <remarks>
/// An unidentified caller is answered 401. A token this service could not obtain for an onward call is
/// never the caller's problem: 503 when waiting may help, 500 when it will not. Neither carries the
/// exception message, which names the provider and can quote the request that was refused.
/// </remarks>
internal sealed class AuthenticationExceptionMapper : IExceptionErrorMapper
{
    /// <inheritdoc />
    public IReadOnlyList<ErrorDefinition>? Map(HttpContext httpContext, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            NotAuthenticatedException =>
            [
                Err.NotAuthenticated(
                    AuthenticationErrors.NoPrincipal,
                    "The request is not authenticated."),
            ],
            ClientAuthenticationException client => [Onward(client)],

            // Null, so every mapper registered after this one still gets its turn.
            _ => null,
        };
    }

    /// <summary>
    /// Reports a failure to obtain a token for an onward call.
    /// </summary>
    /// <param name="failure">The failure to report.</param>
    /// <returns>The error describing it.</returns>
    private static ErrorDefinition Onward(ClientAuthenticationException failure)
    {
        // The reason only. The message names the authority and the client, which are this service's
        // deployment details rather than anything the caller asked about.
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["reason"] = failure.Reason.ToString(),
        };

        return failure.Reason == ClientAuthenticationFailure.Unavailable
            ? Err.Unavailable(
                AuthenticationErrors.ClientTokenUnavailable,
                "A service this request depends on could not be reached.",
                payload)
            : Err.Internal(
                AuthenticationErrors.ClientMisconfigured,
                "This service could not authenticate itself to a service it depends on.",
                payload);
    }
}
