namespace ApricotFramework.Authentication.TokenExchange;

/// <summary>
/// Supplies the token representing whoever this service is currently acting for.
/// </summary>
/// <remarks>
/// <para>
/// Separate from the authenticator because where the subject comes from is a property of the host,
/// not of the grant. A web application reads it off the request being served; a worker reads it
/// from the message it is processing. Neither belongs in a library that only knows OAuth.
/// </para>
/// <para>
/// Returning null means there is nobody to act for, and an exchange then fails rather than falling
/// back to acting as the service itself — that substitution is the mistake this whole arrangement
/// exists to prevent.
/// </para>
/// </remarks>
public interface ISubjectTokenProvider
{
    /// <summary>
    /// Gets the token to act on behalf of if there is one.
    /// </summary>
    /// <param name="cancellationToken">The token to cancel with.</param>
    /// <returns>The subject token, or null when nobody is being acted for.</returns>
    ValueTask<SubjectToken?> GetSubjectTokenAsync(CancellationToken cancellationToken = default);
}
