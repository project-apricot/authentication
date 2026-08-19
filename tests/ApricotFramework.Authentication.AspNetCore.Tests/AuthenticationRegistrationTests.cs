using System.Text;
using ApricotFramework.Authentication.AspNetCore.Extensions;
using ApricotFramework.Authentication.AspNetCore.Impl;
using ApricotFramework.Authentication.AspNetCore.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class AuthenticationRegistrationTests
{
    [Fact]
    public void AddJwtBearerAuthentication_BindsThePredecessorsConfigurationShape()
    {
        // Verbatim from the library this replaces. Existing appsettings.json files and
        // Authentication__Client__ClientSecret environment variables have to keep working.
        using var provider = FromJson("""
            {
              "Authentication": {
                "Authority": "https://demo.duendesoftware.com",
                "ValidAudiences": [ "api" ],
                "AllowInsecure": false,
                "SkipIssuerValidation": false,
                "Client": {
                  "ClientId": "m2m",
                  "ClientSecret": "secret"
                }
              }
            }
            """);

        var settings = provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value;

        Assert.Equal("https://demo.duendesoftware.com", settings.Authority);
        Assert.Equal(["api"], settings.ValidAudiences);
        Assert.False(settings.AllowInsecure);
        Assert.False(settings.SkipIssuerValidation);
        Assert.Equal("m2m", settings.Client.ClientId);
        Assert.Equal("secret", settings.Client.ClientSecret);
    }

    [Fact]
    public void AddJwtBearerAuthentication_AppliesTheAudiencesToTheHandler()
    {
        using var provider = Build(Settings(audiences: ["orders", "billing"]));

        var bearer = Bearer(provider);

        Assert.True(bearer.TokenValidationParameters.ValidateAudience);
        Assert.Equal(["orders", "billing"], bearer.TokenValidationParameters.ValidAudiences);

        // Audience is left alone deliberately: it and ValidAudiences feed the same check, and setting
        // both invites them to disagree.
        Assert.Null(bearer.Audience);
    }

    [Fact]
    public void AddJwtBearerAuthentication_ByDefault_RequiresTheAccessTokenType()
    {
        using var provider = Build(Settings());

        Assert.Equal(["at+jwt"], Bearer(provider).TokenValidationParameters.ValidTypes);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithConfiguredTokenTypes_ReplacesTheDefaultRatherThanAddingToIt()
    {
        // A pre-populated list bound from configuration would be appended to, leaving 'at+jwt' in place
        // and quietly accepting more than was configured.
        using var provider = Build(Settings(tokenTypes: ["JWT"]));

        Assert.Equal(["JWT"], Bearer(provider).TokenValidationParameters.ValidTypes);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithTokenTypeValidationOff_ChecksNone()
    {
        // Null, not an empty list: an empty ValidTypes rejects every token instead of skipping the check.
        var settings = Settings();
        settings["Authentication:ValidateTokenType"] = "false";

        Assert.Null(Bearer(Build(settings)).TokenValidationParameters.ValidTypes);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithAnEmptyConfiguredTokenTypeList_FallsBackToTheDefault()
    {
        // The binder reads an empty JSON array as no value at all, so an empty list cannot be
        // configured. That is why turning the check off is a flag of its own rather than an empty list.
        using var provider = FromJson("""
            {
              "Authentication": {
                "Authority": "https://idp.example.com",
                "ValidAudiences": [ "api" ],
                "ValidTokenTypes": []
              }
            }
            """);

        Assert.Null(provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value.ValidTokenTypes);
        Assert.Equal(["at+jwt"], Bearer(provider).TokenValidationParameters.ValidTypes);
    }

    [Fact]
    public void AddJwtBearerAuthentication_TurnsOffInboundClaimMapping()
    {
        // Keeps 'sub' and 'client_id' under the names the token gave them.
        Assert.False(Bearer(Build(Settings())).MapInboundClaims);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutAllowInsecure_RequiresHttpsMetadataAndKeepsTheDefaultBackchannel()
    {
        var bearer = Bearer(Build(Settings()));

        Assert.True(bearer.RequireHttpsMetadata);
        Assert.Null(bearer.BackchannelHttpHandler);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithAllowInsecure_PermitsHttpMetadataAndReplacesTheBackchannel()
    {
        var settings = Settings(authority: "http://localhost:5001");
        settings["Authentication:AllowInsecure"] = "true";

        var bearer = Bearer(Build(settings));

        Assert.False(bearer.RequireHttpsMetadata);
        Assert.NotNull(bearer.BackchannelHttpHandler);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithSkipIssuerValidation_TurnsTheIssuerCheckOff()
    {
        var settings = Settings();
        settings["Authentication:SkipIssuerValidation"] = "true";

        Assert.False(Bearer(Build(settings)).TokenValidationParameters.ValidateIssuer);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutSkipIssuerValidation_LeavesTheIssuerChecked()
    {
        Assert.True(Bearer(Build(Settings())).TokenValidationParameters.ValidateIssuer);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithValidIssuers_AppliesThem()
    {
        var settings = Settings();
        settings["Authentication:ValidIssuers:0"] = "https://idp.internal";
        settings["Authentication:ValidIssuers:1"] = "https://idp.example.com";

        var validation = Bearer(Build(settings)).TokenValidationParameters;

        Assert.Equal(["https://idp.internal", "https://idp.example.com"], validation.ValidIssuers);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithClockSkew_AppliesIt()
    {
        var settings = Settings();
        settings["Authentication:ClockSkew"] = "00:00:45";

        Assert.Equal(TimeSpan.FromSeconds(45), Bearer(Build(settings)).TokenValidationParameters.ClockSkew);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutClockSkew_LeavesTheFrameworkDefault()
    {
        // Five minutes, which is what the framework picks and what a deployment with synchronised
        // clocks does not need changed.
        Assert.Equal(
            TimeSpan.FromMinutes(5),
            Bearer(Build(Settings())).TokenValidationParameters.ClockSkew);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithClaimTypes_AppliesThem()
    {
        var settings = Settings();
        settings["Authentication:NameClaimType"] = "preferred_username";
        settings["Authentication:RoleClaimType"] = "groups";

        var validation = Bearer(Build(settings)).TokenValidationParameters;

        Assert.Equal("preferred_username", validation.NameClaimType);
        Assert.Equal("groups", validation.RoleClaimType);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WhenAConsumerConfiguresTheSchemeAfterwards_TheConsumerWins()
    {
        // The documented extension point. If registration order went the other way, the settings would
        // silently undo whatever a host configured.
        var configuration = Configuration(Settings());
        var services = new ServiceCollection();

        services.AddJwtBearerAuthentication(configuration);
        services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            options => options.TokenValidationParameters.ValidTypes = ["custom+jwt"]);

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal(["custom+jwt"], Bearer(provider).TokenValidationParameters.ValidTypes);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithACustomScheme_ConfiguresThatScheme()
    {
        var configuration = Configuration(Settings());
        var services = new ServiceCollection();

        services.AddJwtBearerAuthentication(configuration, "InternalBearer");

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.Equal("https://idp.example.com", Bearer(provider, "InternalBearer").Authority);
    }

    [Fact]
    public void AddClientAuthentication_RegistersTheAuthenticatorAndTheCache()
    {
        using var provider = Build(Settings(), resourceServer: false);

        Assert.IsType<ConfigAwareClientAuthenticator>(provider.GetRequiredService<IClientAuthenticator>());
        Assert.IsType<InMemoryClientAuthenticationCache>(provider.GetRequiredService<IClientAuthenticationCache>());
    }

    [Fact]
    public void AddClientAuthentication_WhenACacheIsAlreadyRegistered_KeepsIt()
    {
        // Registered with TryAdd throughout, so a distributed cache can be substituted without this
        // library having to know about it.
        using var provider = Build(
            Settings(),
            resourceServer: false,
            configure: services => services.AddSingleton<IClientAuthenticationCache, SubstituteCache>());

        Assert.IsType<SubstituteCache>(provider.GetRequiredService<IClientAuthenticationCache>());
    }

    [Fact]
    public void AddClientAuthentication_AppliesTheRequestTimeoutToTheNamedClient()
    {
        var settings = Settings();
        settings["Authentication:Client:RequestTimeout"] = "00:00:07";

        using var provider = Build(settings, resourceServer: false);

        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(AuthenticationHttpClients.Token);

        Assert.Equal(TimeSpan.FromSeconds(7), client.Timeout);
    }

    [Fact]
    public void AddClientAuthentication_ByDefault_AppliesAThirtySecondTimeout()
    {
        // The framework default of 100 seconds holds a request open long enough for a slow provider to
        // become an availability problem of its own.
        using var provider = Build(Settings(), resourceServer: false);

        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(AuthenticationHttpClients.Token);

        Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutAudiences_FailsValidation()
    {
        var settings = Settings(audiences: []);

        using var provider = Build(settings);

        var failure = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value);

        Assert.Contains("ValidAudiences", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutAudiencesAndValidationOff_Passes()
    {
        var settings = Settings(audiences: []);
        settings["Authentication:ValidateAudience"] = "false";

        using var provider = Build(settings);

        var bound = provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value;

        Assert.False(bound.ValidateAudience);
        Assert.False(Bearer(provider).TokenValidationParameters.ValidateAudience);
    }

    [Fact]
    public void AddClientAuthentication_WithoutAResourceServer_DoesNotRequireAnAudience()
    {
        // A worker that only calls other services has no audience of its own to name.
        using var provider = Build(Settings(audiences: []), resourceServer: false);

        Assert.NotNull(provider.GetRequiredService<IOptions<ServiceAuthenticationOptions>>().Value);
    }

    [Fact]
    public void AddJwtBearerAuthentication_WithoutServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AuthenticationRegistrationExtensions.AddJwtBearerAuthentication(null!, Configuration(Settings())));
    }

    [Fact]
    public void AddClientAuthentication_WithoutConfiguration_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddClientAuthentication(null!));
    }

    private static JwtBearerOptions Bearer(
        ServiceProvider provider,
        string scheme = JwtBearerDefaults.AuthenticationScheme)
    {
        return provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(scheme);
    }

    private static Dictionary<string, string?> Settings(
        string authority = "https://idp.example.com",
        IReadOnlyList<string>? audiences = null,
        IReadOnlyList<string>? tokenTypes = null)
    {
        var settings = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["Authentication:Authority"] = authority,
        };

        foreach (var (audience, index) in (audiences ?? ["api"]).Select((value, index) => (value, index)))
        {
            settings[$"Authentication:ValidAudiences:{index}"] = audience;
        }

        foreach (var (tokenType, index) in (tokenTypes ?? []).Select((value, index) => (value, index)))
        {
            settings[$"Authentication:ValidTokenTypes:{index}"] = tokenType;
        }

        return settings;
    }

    private static IConfiguration Configuration(Dictionary<string, string?> settings)
    {
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }

    private static ServiceProvider Build(
        Dictionary<string, string?> settings,
        bool resourceServer = true,
        Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();

        configure?.Invoke(services);

        var configuration = Configuration(settings);

        if (resourceServer)
        {
            services.AddJwtBearerAuthentication(configuration);
        }
        else
        {
            services.AddClientAuthentication(configuration);
        }

        return services.BuildServiceProvider(validateScopes: true);
    }

    private static ServiceProvider FromJson(string json)
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        var services = new ServiceCollection();

        services.AddJwtBearerAuthentication(configuration);

        return services.BuildServiceProvider(validateScopes: true);
    }

    private sealed class SubstituteCache : IClientAuthenticationCache
    {
        public ValueTask<AuthenticatedClientContext?> GetTokenAsync(
            ClientAuthenticationParameters parameters,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<AuthenticatedClientContext?>(null);
        }

        public ValueTask SetTokenAsync(
            ClientAuthenticationParameters parameters,
            AuthenticatedClientContext context,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }

        public ValueTask<string?> GetTokenEndpointAsync(string authority, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<string?>(null);
        }

        public ValueTask SetTokenEndpointAsync(
            string authority,
            string tokenEndpoint,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.CompletedTask;
        }
    }
}
