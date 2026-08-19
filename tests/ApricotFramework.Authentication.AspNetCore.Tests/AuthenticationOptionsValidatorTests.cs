using ApricotFramework.Authentication.AspNetCore.Impl;
using ApricotFramework.Authentication.AspNetCore.Options;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

public class AuthenticationOptionsValidatorTests
{
    [Fact]
    public void Validate_WithNoClientConfigured_Passes()
    {
        // A service that only validates inbound tokens configures no client at all.
        var result = Client().Validate(null, new ServiceAuthenticationOptions { Authority = "https://idp.example.com" });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithASecretButNoClientId_Fails()
    {
        var options = Options();
        options.Client.ClientId = null;
        options.Client.ClientSecret = "s3cret";

        Assert.Contains("ClientId", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithAClientAndNoAuthorityAnywhere_Fails()
    {
        var options = Options(authority: null);
        options.Client.Authority = null;

        Assert.Contains("no authority", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithAClientAndOnlyTheInboundAuthority_Passes()
    {
        // The usual arrangement: one provider both issues and is validated against.
        Assert.True(Client().Validate(null, Options()).Succeeded);
    }

    [Fact]
    public void Validate_WithAnHttpClientAuthority_Fails()
    {
        var options = Options();
        options.Client.Authority = "http://localhost:5001";

        Assert.Contains("not https", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithAnHttpClientAuthorityAndAllowInsecure_Passes()
    {
        var options = Options();
        options.Client.Authority = "http://localhost:5001";
        options.AllowInsecure = true;

        Assert.True(Client().Validate(null, options).Succeeded);
    }

    [Theory]
    [InlineData("idp.example.com")]
    [InlineData("ftp://idp.example.com")]
    [InlineData("not a url")]
    public void Validate_WithAnUnusableClientAuthority_Fails(string authority)
    {
        var options = Options();
        options.Client.Authority = authority;

        Assert.Contains("absolute http", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithANonPositiveRequestTimeout_Fails(int seconds)
    {
        var options = Options();
        options.Client.RequestTimeout = TimeSpan.FromSeconds(seconds);

        Assert.Contains("RequestTimeout", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithANegativeTokenExpirySkew_Fails()
    {
        var options = Options();
        options.Client.TokenExpirySkew = TimeSpan.FromSeconds(-30);

        Assert.Contains("TokenExpirySkew", Failures(Client().Validate(null, options)), StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_ReportsEveryFailureRatherThanStoppingAtTheFirst()
    {
        var options = Options(authority: null);
        options.Client.ClientId = null;
        options.Client.ClientSecret = "s3cret";
        options.Client.RequestTimeout = TimeSpan.Zero;

        var result = Client().Validate(null, options);

        Assert.NotNull(result.Failures);
        Assert.True(result.Failures.Count() >= 3, "each mistake should be reported, not just the first");
    }

    [Fact]
    public void Validate_WithAllowInsecure_WarnsOnceHoweverOftenOptionsAreValidated()
    {
        // Options are validated once for startup validation and again when something first resolves
        // them, so an unconditional warning repeats every message and makes the log look broken.
        var logger = new RecordingLogger<ClientAuthenticationOptionsValidator>();
        var validator = new ClientAuthenticationOptionsValidator(logger);
        var options = Options();
        options.AllowInsecure = true;

        validator.Validate(null, options);
        validator.Validate(null, options);
        validator.Validate(null, options);

        Assert.Single(logger.Warnings);
        Assert.Contains("AllowInsecure", logger.Warnings[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithoutAllowInsecure_DoesNotWarn()
    {
        var logger = new RecordingLogger<ClientAuthenticationOptionsValidator>();

        new ClientAuthenticationOptionsValidator(logger).Validate(null, Options());

        Assert.Empty(logger.Warnings);
    }

    [Fact]
    public void ResourceServerValidate_WithoutAnAuthority_Fails()
    {
        var failures = Failures(ResourceServer().Validate(null, Options(authority: null)));

        Assert.Contains("Authentication:Authority is required", failures, StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceServerValidate_WithoutAudiences_FailsAndNamesTheWayOut()
    {
        // The predecessor turned this into "every token is rejected", which reads as a broken provider.
        var options = Options();
        options.ValidAudiences = null;

        var failures = Failures(ResourceServer().Validate(null, options));

        Assert.Contains("ValidAudiences", failures, StringComparison.Ordinal);
        Assert.Contains("ValidateAudience", failures, StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceServerValidate_WithAudienceValidationOff_Passes()
    {
        var options = Options();
        options.ValidAudiences = null;
        options.ValidateAudience = false;

        Assert.True(ResourceServer().Validate(null, options).Succeeded);
    }

    [Fact]
    public void ResourceServerValidate_DoesNotRepeatTheClientChecks()
    {
        // The two validators are independent so that a host registering both reports each problem once.
        var options = Options(authority: null);
        options.Client.ClientId = null;
        options.Client.ClientSecret = "s3cret";

        var failures = Failures(ResourceServer().Validate(null, options));

        Assert.DoesNotContain("ClientId", failures, StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceServerValidate_WithSkipIssuerValidation_WarnsOnce()
    {
        var logger = new RecordingLogger<ResourceServerOptionsValidator>();
        var validator = new ResourceServerOptionsValidator(logger);
        var options = Options();
        options.SkipIssuerValidation = true;

        validator.Validate(null, options);
        validator.Validate(null, options);

        Assert.Single(logger.Warnings);
        Assert.Contains("SkipIssuerValidation", logger.Warnings[0], StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceServerValidate_WithTokenTypeValidationOff_WarnsOnce()
    {
        var logger = new RecordingLogger<ResourceServerOptionsValidator>();
        var validator = new ResourceServerOptionsValidator(logger);
        var options = Options();
        options.ValidateTokenType = false;

        validator.Validate(null, options);
        validator.Validate(null, options);

        Assert.Single(logger.Warnings);
        Assert.Contains("ValidateTokenType", logger.Warnings[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_WithoutOptions_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Client().Validate(null, null!));
        Assert.Throws<ArgumentNullException>(() => ResourceServer().Validate(null, null!));
    }

    private static ClientAuthenticationOptionsValidator Client()
    {
        return new ClientAuthenticationOptionsValidator(new RecordingLogger<ClientAuthenticationOptionsValidator>());
    }

    private static ResourceServerOptionsValidator ResourceServer()
    {
        return new ResourceServerOptionsValidator(new RecordingLogger<ResourceServerOptionsValidator>());
    }

    private static string Failures(Microsoft.Extensions.Options.ValidateOptionsResult result)
    {
        return string.Join(" | ", result.Failures ?? []);
    }

    private static ServiceAuthenticationOptions Options(string? authority = "https://idp.example.com")
    {
        return new ServiceAuthenticationOptions
        {
            Authority = authority,
            ValidAudiences = ["api"],
            Client = new ClientAuthenticationOptions
            {
                ClientId = "svc",
                ClientSecret = "s3cret",
            },
        };
    }
}
