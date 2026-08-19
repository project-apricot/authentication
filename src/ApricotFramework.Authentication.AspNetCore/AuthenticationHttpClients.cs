namespace ApricotFramework.Authentication.AspNetCore;

/// <summary>
/// The named clients this package registers, so a host can configure their handlers further.
/// </summary>
public static class AuthenticationHttpClients
{
    /// <summary>
    /// The client token requests and provider metadata reads are sent on.
    /// </summary>
    /// <remarks>
    /// Configure it through <c>AddHttpClient(AuthenticationHttpClients.Token)</c> to add a retry policy
    /// or a proxy. The timeout and, when insecure transport is permitted, the handler are set already.
    /// </remarks>
    public const string Token = "ApricotFramework.Authentication.Token";
}
