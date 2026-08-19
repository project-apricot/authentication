using ApricotFramework.Authentication;
using ApricotFramework.Authentication.AspNetCore;
using ApricotFramework.Authentication.AspNetCore.Extensions;
using Microsoft.AspNetCore.Mvc;

namespace ApricotFramework.Authentication.Examples.Web.Controllers;

/// <summary>
/// Both halves of the library, and what each failure answers with.
/// </summary>
[ApiController]
[Route("api")]
public class DemoController : ControllerBase
{
    /// <summary>
    /// The client obtaining tokens for onward calls.
    /// </summary>
    private readonly IClientAuthenticator authenticator;

    /// <summary>
    /// Initializes a new instance of the <see cref="DemoController"/> class.
    /// </summary>
    /// <param name="authenticator">The client obtaining tokens for onward calls.</param>
    public DemoController(IClientAuthenticator authenticator)
    {
        this.authenticator = authenticator;
    }

    /// <summary>
    /// Reports who the caller is. Works for a person and for a service alike.
    /// </summary>
    /// <returns>The principal the token describes.</returns>
    [HttpGet("whoami")]
    [BearerAuthorize]
    public object WhoAmI()
    {
        var principal = this.HttpContext.GetPrincipal();

        return new
        {
            principal.Subject,
            principal.ClientId,
            principal.Scopes,
        };
    }

    /// <summary>
    /// Reports what the caller is, without requiring one.
    /// </summary>
    /// <returns>The principal, or a note that there is none.</returns>
    [HttpGet("whoami-or-anonymous")]
    public object WhoAmIOrAnonymous()
    {
        // The non-throwing path, for an endpoint that serves anonymous callers differently rather than
        // refusing them.
        return this.HttpContext.TryGetPrincipal(out var principal)
            ? new { Authenticated = true, principal.Subject, principal.ClientId }
            : new { Authenticated = false, Subject = (string?)null, ClientId = (string?)null };
    }

    /// <summary>
    /// Obtains a service-to-service token and describes it.
    /// </summary>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>What was obtained, without the credential itself.</returns>
    [HttpGet("token")]
    public async Task<object> Token(CancellationToken cancellationToken)
    {
        var context = await this.authenticator.AuthenticateAsync(
            new ClientAuthenticationParameters { Scopes = ["api"] },
            cancellationToken);

        // The token is a bearer credential, so it is described rather than returned. An endpoint that
        // handed it out would let any caller borrow this service's identity.
        return new
        {
            context.TokenType,
            context.ExpiresAt,
            TokenLength = context.Token.Length,
        };
    }

    /// <summary>
    /// Fails to reach a provider, to show that an onward failure is not the caller's fault.
    /// </summary>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>Never; this always fails.</returns>
    /// <remarks>
    /// Answers 503 with kind <c>unavailable</c>. Not 401: the caller authenticated perfectly well, and
    /// it is this service that could not authenticate itself onwards.
    /// </remarks>
    [HttpGet("downstream-unreachable")]
    public Task<object> DownstreamUnreachable(CancellationToken cancellationToken)
    {
        return this.authenticator.DoAuthenticatedAsync<object>(
            (_, _) => Task.FromResult<object>(new { Reached = true }),
            new ClientAuthenticationParameters { Authority = "https://localhost:9" },
            cancellationToken);
    }

    /// <summary>
    /// Fails on a bad authority, to show a deployment fault answering as one.
    /// </summary>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>Never; this always fails.</returns>
    /// <remarks>
    /// Answers 500 with kind <c>internal</c>, because no amount of retrying fixes a wrong setting.
    /// </remarks>
    [HttpGet("downstream-misconfigured")]
    public Task<object> DownstreamMisconfigured(CancellationToken cancellationToken)
    {
        return this.authenticator.DoAuthenticatedAsync<object>(
            (_, _) => Task.FromResult<object>(new { Reached = true }),
            new ClientAuthenticationParameters { Authority = "not-a-url" },
            cancellationToken);
    }
}
