using ApricotFramework.ErrorDefinitions.AspNetCore.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.Authentication.ErrorDefinitions.Extensions;

/// <summary>
/// Registers what turns authentication failures into problem+json.
/// </summary>
public static class AuthenticationErrorDefinitionsServiceCollectionExtensions
{
    /// <summary>
    /// Adds the authentication exception mapper and gives the empty 401 and 403 a body.
    /// </summary>
    /// <param name="services">The services to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    /// <remarks>
    /// A mapper with no handler does nothing. The host still calls <c>AddErrorDefinitions</c> and
    /// <c>UseExceptionHandler</c>; where the handler sits in the pipeline is its decision.
    /// <para>
    /// The 401 and 403 bodies cover answers from the authorization middleware, which is every endpoint
    /// carrying a policy. A challenge issued from an endpoint by hand is left alone.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddAuthenticationErrorDefinitions(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddExceptionErrorMapper<AuthenticationExceptionMapper>();

        services.AddAuthorizationResultErrors();

        return services;
    }

    /// <summary>
    /// Wraps whichever authorization result handler is registered so that it answers with a body.
    /// </summary>
    /// <param name="services">The services to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    private static IServiceCollection AddAuthorizationResultErrors(this IServiceCollection services)
    {
        // Already wrapped. A marker rather than a search for the writer itself, because it is registered
        // through a factory and so has no implementation type to match on.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(WriterRegistered)))
        {
            return services;
        }

        services.AddSingleton<WriterRegistered>();

        // Captured now rather than resolved later: registering this handler is what stops the framework's
        // own TryAdd from taking effect, so by resolution time there would be nothing left to find.
        var existing = services.LastOrDefault(descriptor =>
            descriptor.ServiceType == typeof(IAuthorizationMiddlewareResultHandler) && !descriptor.IsKeyedService);

        services.AddSingleton<IAuthorizationMiddlewareResultHandler>(provider =>
            new AuthorizationResultErrorWriter(Decorated(provider, existing)));

        return services;
    }

    /// <summary>
    /// Builds the handler that was registered before this one, or the framework's own.
    /// </summary>
    /// <param name="provider">The provider to resolve dependencies from.</param>
    /// <param name="descriptor">The registration found at the time, if there was one.</param>
    /// <returns>The handler to decorate.</returns>
    private static IAuthorizationMiddlewareResultHandler Decorated(
        IServiceProvider provider,
        ServiceDescriptor? descriptor)
    {
        if (descriptor?.ImplementationInstance is IAuthorizationMiddlewareResultHandler instance)
        {
            return instance;
        }

        if (descriptor?.ImplementationFactory is { } factory)
        {
            return (IAuthorizationMiddlewareResultHandler)factory(provider);
        }

        if (descriptor?.ImplementationType is { } type)
        {
            return (IAuthorizationMiddlewareResultHandler)ActivatorUtilities.CreateInstance(provider, type);
        }

        // Nothing registered yet, which happens when this is called before AddAuthorization. The
        // framework's TryAdd would have produced exactly this.
        return new AuthorizationMiddlewareResultHandler();
    }

    /// <summary>
    /// Records that the decorator is in place, so a second call does not nest another one.
    /// </summary>
    private sealed class WriterRegistered;
}
