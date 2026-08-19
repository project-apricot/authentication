using ApricotFramework.Authentication.AspNetCore.Exceptions;
using ApricotFramework.ErrorDefinitions;
using ApricotFramework.ErrorDefinitions.AspNetCore;
using ApricotFramework.ErrorDefinitions.AspNetCore.Extensions;
using ApricotFramework.Authentication.ErrorDefinitions.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace ApricotFramework.Authentication.ErrorDefinitions.Tests;

public class AuthenticationExceptionMapperTests
{
    [Fact]
    public void Map_WithAnUnrecognisedException_ReturnsNull()
    {
        // Mappers are consulted in order and the first non-null answer wins, so answering everything
        // would silently disable every mapper after this one.
        Assert.Null(Mapper().Map(new DefaultHttpContext(), new InvalidTimeZoneException("unrelated")));
    }

    [Fact]
    public void Map_WithNoPrincipal_ReportsNotAuthenticated()
    {
        var errors = Mapper().Map(new DefaultHttpContext(), new NotAuthenticatedException("no principal"));

        var error = Assert.Single(errors!);

        Assert.Equal(ErrorKinds.NotAuthenticated, error.Kind);
        Assert.Equal(AuthenticationErrors.NoPrincipal, error.Code);
    }

    [Fact]
    public void Map_WhenTheProviderWasUnreachable_ReportsUnavailable()
    {
        // Retryable, and a fault of a dependency rather than of this service's configuration.
        var errors = Mapper().Map(
            new DefaultHttpContext(),
            new ClientAuthenticationException(ClientAuthenticationFailure.Unavailable, "unreachable"));

        var error = Assert.Single(errors!);

        Assert.Equal(ErrorKinds.Unavailable, error.Kind);
        Assert.Equal(AuthenticationErrors.ClientTokenUnavailable, error.Code);
        Assert.Equal(503, ErrorKindStatus.ToHttpStatusCode(error.Kind));
    }

    [Theory]
    [InlineData(ClientAuthenticationFailure.InvalidCredentials)]
    [InlineData(ClientAuthenticationFailure.InvalidConfiguration)]
    [InlineData(ClientAuthenticationFailure.InvalidScope)]
    [InlineData(ClientAuthenticationFailure.Unknown)]
    public void Map_WhenThisServiceCouldNotAuthenticateItself_ReportsInternalRatherThanNotAuthenticated(
        ClientAuthenticationFailure reason)
    {
        // The whole point of the bridge: the caller presented a good credential, so answering 401 would
        // tell them to do something that cannot help and would blame them for our misconfiguration.
        var errors = Mapper().Map(
            new DefaultHttpContext(),
            new ClientAuthenticationException(reason, "rejected"));

        var error = Assert.Single(errors!);

        Assert.Equal(ErrorKinds.Internal, error.Kind);
        Assert.Equal(AuthenticationErrors.ClientMisconfigured, error.Code);
        Assert.Equal(500, ErrorKindStatus.ToHttpStatusCode(error.Kind));
    }

    [Fact]
    public void Map_WithAnOnwardFailure_CarriesTheReasonInThePayload()
    {
        var errors = Mapper().Map(
            new DefaultHttpContext(),
            new ClientAuthenticationException(ClientAuthenticationFailure.InvalidScope, "refused"));

        var error = Assert.Single(errors!);

        Assert.NotNull(error.Payload);
        Assert.Equal(nameof(ClientAuthenticationFailure.InvalidScope), error.Payload["reason"]);
    }

    [Fact]
    public void Map_WithAnOnwardFailure_KeepsTheProviderAndTheSecretOutOfTheAnswer()
    {
        // The message names the authority and the client, and a provider's own error description can
        // quote the request that carried the secret.
        var failure = new ClientAuthenticationException(
            ClientAuthenticationFailure.InvalidCredentials,
            "The provider at 'https://idp.internal.example.com' refused client 'orders-svc': invalid_client.");

        var errors = Mapper().Map(new DefaultHttpContext(), failure);

        var error = Assert.Single(errors!);

        Assert.DoesNotContain("idp.internal.example.com", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("orders-svc", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Map_WithoutAnException_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Mapper().Map(new DefaultHttpContext(), null!));
    }

    private static IExceptionErrorMapper Mapper()
    {
        // Resolved rather than constructed: the mapper is internal by design, and going through the
        // registration proves it is actually reachable by the handler.
        var services = new ServiceCollection();

        services.AddErrorDefinitions();
        services.AddAuthenticationErrorDefinitions();

        using var provider = services.BuildServiceProvider(validateScopes: true);

        return provider.GetServices<IExceptionErrorMapper>()
            .Single(mapper => mapper.GetType().Name == "AuthenticationExceptionMapper");
    }
}
