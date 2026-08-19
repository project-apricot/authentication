using System.Text.Json;
using ApricotFramework.Authentication.ErrorDefinitions.Extensions;
using ApricotFramework.ErrorDefinitions;
using ApricotFramework.ErrorDefinitions.AspNetCore.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.Authentication.ErrorDefinitions.Tests;

public class AuthorizationResultErrorWriterTests
{
    [Fact]
    public async Task HandleAsync_WhenTheAnswerWasUnauthorized_WritesTheProblemDocument()
    {
        // A 401 is not an exception, so it reaches no exception handler, and it is the failure a client
        // meets most often.
        var (handler, inner) = Build(StatusCodes.Status401Unauthorized);
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Challenge());

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal(ErrorProblemDetails.MediaType, context.Response.ContentType);
        Assert.Equal(AuthenticationErrors.NoPrincipal, FirstCode(context));
        Assert.True(inner.Called);
    }

    [Fact]
    public async Task HandleAsync_WhenTheAnswerWasForbidden_WritesTheProblemDocument()
    {
        var (handler, _) = Build(StatusCodes.Status403Forbidden);
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Forbid());

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.Equal(ErrorCodes.AccessDenied, FirstCode(context));
    }

    [Fact]
    public async Task HandleAsync_KeepsTheChallengeHeaderTheFrameworkSet()
    {
        // RFC 6750 requires WWW-Authenticate on a 401. Writing the body by taking the challenge over
        // instead of decorating it is how that header gets lost.
        var (handler, _) = Build(StatusCodes.Status401Unauthorized, challenge: "Bearer error=\"invalid_token\"");
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Challenge());

        Assert.Equal("Bearer error=\"invalid_token\"", context.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task HandleAsync_WhenAuthorizationSucceeded_WritesNothing()
    {
        var (handler, inner) = Build(StatusCodes.Status200OK);
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Success());

        Assert.True(inner.Called);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task HandleAsync_WhenTheInnerHandlerAlreadyWroteABody_LeavesItAlone()
    {
        // A policy that answers for itself keeps its answer; nothing here may overwrite one.
        var (handler, _) = Build(StatusCodes.Status403Forbidden, body: "policy said no");
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Forbid());

        Assert.Equal("policy said no", ReadBody(context));
    }

    [Fact]
    public async Task HandleAsync_WithAStatusItDoesNotOwn_WritesNothing()
    {
        var (handler, _) = Build(StatusCodes.Status409Conflict);
        var context = Context();

        await handler.HandleAsync(Next, context, Policy(), PolicyAuthorizationResult.Forbid());

        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public void AddAuthenticationErrorDefinitions_CalledTwice_DoesNotNestTheDecorator()
    {
        var services = new ServiceCollection();

        services.AddErrorDefinitions();
        services.AddAuthorization();
        services.AddAuthenticationErrorDefinitions();
        services.AddAuthenticationErrorDefinitions();

        // Ours is the only one registered through a factory, so counting those counts the decorators.
        var writers = services.Count(descriptor =>
            descriptor.ServiceType == typeof(IAuthorizationMiddlewareResultHandler)
            && descriptor.ImplementationFactory is not null);

        Assert.Equal(1, writers);
    }

    [Fact]
    public void AddAuthenticationErrorDefinitions_BeforeAddAuthorization_StillResolves()
    {
        // Registering ours is what stops the framework's TryAdd from taking effect, so there has to be a
        // fallback to the handler it would have registered.
        var services = new ServiceCollection();

        services.AddErrorDefinitions();
        services.AddAuthenticationErrorDefinitions();
        services.AddAuthorization();

        using var provider = services.BuildServiceProvider(validateScopes: true);

        var handler = provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>();

        Assert.Equal("AuthorizationResultErrorWriter", handler.GetType().Name);
    }

    [Fact]
    public void AddAuthenticationErrorDefinitions_WithoutServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AuthenticationErrorDefinitionsServiceCollectionExtensions.AddAuthenticationErrorDefinitions(null!));
    }

    private static Task Next(HttpContext context)
    {
        return Task.CompletedTask;
    }

    private static AuthorizationPolicy Policy()
    {
        return new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();
    }

    private static DefaultHttpContext Context()
    {
        var context = new DefaultHttpContext();

        context.Response.Body = new MemoryStream();
        context.Request.Path = "/api/orders";

        return context;
    }

    private static string ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;

        return new StreamReader(context.Response.Body).ReadToEnd();
    }

    private static string? FirstCode(HttpContext context)
    {
        using var document = JsonDocument.Parse(ReadBody(context));

        return document.RootElement.GetProperty("errors")[0].GetProperty("code").GetString();
    }

    private static (IAuthorizationMiddlewareResultHandler Handler, StubResultHandler Inner) Build(
        int status,
        string? challenge = null,
        string? body = null)
    {
        var inner = new StubResultHandler(status, challenge, body);
        var services = new ServiceCollection();

        services.AddErrorDefinitions();

        // Registered first, so the decorator wraps it rather than the framework's own handler.
        services.AddSingleton<IAuthorizationMiddlewareResultHandler>(inner);
        services.AddAuthenticationErrorDefinitions();

        using var provider = services.BuildServiceProvider(validateScopes: true);

        return (provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>(), inner);
    }

    private sealed class StubResultHandler : IAuthorizationMiddlewareResultHandler
    {
        private readonly int status;

        private readonly string? challenge;

        private readonly string? body;

        public StubResultHandler(int status, string? challenge, string? body)
        {
            this.status = status;
            this.challenge = challenge;
            this.body = body;
        }

        public bool Called { get; private set; }

        public async Task HandleAsync(
            RequestDelegate next,
            HttpContext context,
            AuthorizationPolicy policy,
            PolicyAuthorizationResult authorizeResult)
        {
            this.Called = true;
            context.Response.StatusCode = this.status;

            if (this.challenge is not null)
            {
                context.Response.Headers.WWWAuthenticate = this.challenge;
            }

            if (this.body is not null)
            {
                context.Response.ContentType = "text/plain";

                await context.Response.WriteAsync(this.body);
            }
        }
    }
}
