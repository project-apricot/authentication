using ApricotFramework.Authentication.AspNetCore.Impl;
using ApricotFramework.Authentication.AspNetCore.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Extensions;

/// <summary>
/// The extensions for authentication.
/// </summary>
public static class AuthenticationRegistrationExtensions
{
    /// <summary>
    /// Adds JWT bearer validation for inbound requests, and the client for outbound ones.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <param name="configuration">The configuration supplying the <c>Authentication</c> section.</param>
    /// <param name="authenticationScheme">
    /// The scheme to register as, defaulting to <see cref="JwtBearerDefaults.AuthenticationScheme"/>.
    /// </param>
    /// <returns>The authentication builder, so further schemes can be added.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="configuration"/> is null.
    /// </exception>
    /// <remarks>
    /// Both halves, because the client costs nothing until something asks it for a token. To configure
    /// the handler further, configure <see cref="JwtBearerOptions"/> for the same scheme afterwards: a
    /// later configuration wins, so nothing here has to be undone.
    /// </remarks>
    public static AuthenticationBuilder AddJwtBearerAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        string? authenticationScheme = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var scheme = string.IsNullOrWhiteSpace(authenticationScheme)
            ? JwtBearerDefaults.AuthenticationScheme
            : authenticationScheme;

        services.AddClientAuthentication(configuration);

        // Only registered for a host that validates inbound tokens, so a client-only service is not
        // asked for an audience.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<ServiceAuthenticationOptions>, ResourceServerOptionsValidator>());

        var builder = services.AddAuthentication(scheme);

        builder.AddJwtBearer(scheme);

        // Configured through the options pipeline rather than the AddJwtBearer callback, because the
        // settings have to be resolved from the container to be read at all.
        services
            .AddOptions<JwtBearerOptions>(scheme)
            .Configure<IOptionsMonitor<ServiceAuthenticationOptions>>(
                static (bearer, settings) => ApplyBearerSettings(bearer, settings.CurrentValue));

        return builder;
    }

    /// <summary>
    /// Adds the client that obtains tokens for calls this service makes to another.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <param name="configuration">The configuration supplying the <c>Authentication</c> section.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="services"/> or <paramref name="configuration"/> is null.
    /// </exception>
    /// <remarks>
    /// For a worker or a service that calls others without serving authenticated requests itself. A host
    /// calling <see cref="AddJwtBearerAuthentication"/> gets this as well and need not call it.
    /// </remarks>
    public static IServiceCollection AddClientAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddLogging();
        services.AddMemoryCache();

        services
            .AddOptions<ServiceAuthenticationOptions>()
            .Bind(configuration.GetSection(ServiceAuthenticationOptions.SectionName))
            .ValidateOnStart();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<ServiceAuthenticationOptions>, ClientAuthenticationOptionsValidator>());

        services
            .AddHttpClient(AuthenticationHttpClients.Token)
            .ConfigureHttpClient(static (provider, client) =>
                client.Timeout = provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value.Client.RequestTimeout)
            .ConfigurePrimaryHttpMessageHandler(static provider =>
                CreateTokenHandler(provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value));

        services.TryAddSingleton<IClientAuthenticationCache, InMemoryClientAuthenticationCache>();
        services.TryAddSingleton<IClientAuthenticator, ConfigAwareClientAuthenticator>();

        return services;
    }

    /// <summary>
    /// Builds the handler token requests go out through.
    /// </summary>
    /// <param name="settings">The settings deciding whether the provider's certificate is checked.</param>
    /// <returns>The handler to use.</returns>
    private static HttpClientHandler CreateTokenHandler(ServiceAuthenticationOptions settings)
    {
        var handler = new HttpClientHandler();

        if (settings.AllowInsecure)
        {
            // Development only, and warned about at startup. Accepting any certificate means the
            // provider on the other end is unauthenticated, so the secret goes to whoever answers.
            handler.ServerCertificateCustomValidationCallback = static (_, _, _, _) => true;
        }

        return handler;
    }

    /// <summary>
    /// Decides which token type headers to accept.
    /// </summary>
    /// <param name="settings">The settings to read.</param>
    /// <returns>The accepted types.</returns>
    /// <remarks>
    /// The setting is nullable rather than pre-populated because the configuration binder appends to a
    /// list that already has entries, which would leave the default in place alongside whatever a host
    /// configured.
    /// </remarks>
    private static IReadOnlyList<string> EffectiveTokenTypes(ServiceAuthenticationOptions settings)
    {
        return settings.ValidTokenTypes is { } configured
            ? [.. configured]
            : ServiceAuthenticationOptions.DefaultValidTokenTypes;
    }

    /// <summary>
    /// Projects the settings onto the bearer handler.
    /// </summary>
    /// <param name="bearer">The handler options to configure.</param>
    /// <param name="settings">The settings to apply.</param>
    private static void ApplyBearerSettings(JwtBearerOptions bearer, ServiceAuthenticationOptions settings)
    {
        bearer.Authority = settings.Authority;

        // Claims keep the names the token gave them, so 'sub' and 'client_id' can be read as written
        // rather than as the legacy identifiers the mapping renames them to.
        bearer.MapInboundClaims = false;
        bearer.RequireHttpsMetadata = !settings.AllowInsecure;

        if (settings.AllowInsecure)
        {
            bearer.BackchannelHttpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = static (_, _, _, _) => true,
            };
        }

        var validation = bearer.TokenValidationParameters;

        // ValidAudiences alone, never Audience as well: the two are separate inputs to the same check
        // and setting both invites them to disagree.
        validation.ValidateAudience = settings.ValidateAudience;
        validation.ValidAudiences = settings.ValidAudiences ?? [];

        validation.ValidateIssuer = !settings.SkipIssuerValidation;

        if (settings.ValidIssuers is { Count: > 0 } issuers)
        {
            validation.ValidIssuers = issuers;
        }

        // Null rather than an empty list: an empty ValidTypes rejects every token, where null is what
        // skips the check.
        validation.ValidTypes = settings.ValidateTokenType && EffectiveTokenTypes(settings) is { Count: > 0 } tokenTypes
            ? tokenTypes
            : null;

        if (settings.ClockSkew is { } skew)
        {
            validation.ClockSkew = skew;
        }

        if (!string.IsNullOrWhiteSpace(settings.NameClaimType))
        {
            validation.NameClaimType = settings.NameClaimType;
        }

        if (!string.IsNullOrWhiteSpace(settings.RoleClaimType))
        {
            validation.RoleClaimType = settings.RoleClaimType;
        }
    }
}
