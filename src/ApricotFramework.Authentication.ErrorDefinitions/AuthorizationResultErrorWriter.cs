using ApricotFramework.ErrorDefinitions;
using ApricotFramework.ErrorDefinitions.AspNetCore.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace ApricotFramework.Authentication.ErrorDefinitions;

/// <summary>
/// Gives the empty 401 and 403 a body in the same shape as every other failure.
/// </summary>
/// <remarks>
/// Neither answer is an exception, so neither reaches an exception handler, and a service otherwise
/// answers in one contract for every failure except the two most common ones a client meets.
/// <para>
/// It decorates the framework's handler and writes only after it has run, so the status and the
/// <c>WWW-Authenticate</c> header RFC 6750 requires are the framework's own.
/// </para>
/// </remarks>
internal sealed class AuthorizationResultErrorWriter : IAuthorizationMiddlewareResultHandler
{
    /// <summary>
    /// The handler that decides the answer, and that this one only adds a body to.
    /// </summary>
    private readonly IAuthorizationMiddlewareResultHandler inner;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationResultErrorWriter"/> class.
    /// </summary>
    /// <param name="inner">The handler to decorate.</param>
    public AuthorizationResultErrorWriter(IAuthorizationMiddlewareResultHandler inner)
    {
        ArgumentNullException.ThrowIfNull(inner);

        this.inner = inner;
    }

    /// <inheritdoc />
    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authorizeResult);

        await this.inner.HandleAsync(next, context, policy, authorizeResult).ConfigureAwait(false);

        // On success the call above ran the rest of the pipeline, so whatever the endpoint answered is
        // already the response.
        if (authorizeResult.Succeeded || context.Response.HasStarted)
        {
            return;
        }

        // Only an answer left empty is filled in, so a policy that wrote its own body keeps it.
        if (context.Response.ContentLength is > 0 || context.Response.ContentType is not null)
        {
            return;
        }

        var errors = context.Response.StatusCode switch
        {
            StatusCodes.Status401Unauthorized => new[]
            {
                Err.NotAuthenticated(AuthenticationErrors.NoPrincipal, "The request is not authenticated."),
            },
            StatusCodes.Status403Forbidden => new[]
            {
                Err.AccessDenied(message: "The request is not permitted."),
            },
            _ => null,
        };

        if (errors is null)
        {
            return;
        }

        // The status the framework already chose, so the body cannot disagree with the headers.
        await context
            .WriteErrorProblemDetailsAsync(errors, context.Response.StatusCode, context.RequestAborted)
            .ConfigureAwait(false);
    }
}
