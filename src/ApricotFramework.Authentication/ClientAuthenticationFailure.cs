namespace ApricotFramework.Authentication;

/// <summary>
/// Why a token could not be obtained, at the granularity a caller can act on.
/// </summary>
/// <remarks>
/// The distinction that matters operationally is whether waiting helps. <see cref="Unavailable"/>
/// says it might; everything else says a person has to change something.
/// </remarks>
public enum ClientAuthenticationFailure
{
    /// <summary>
    /// The provider answered, but not in a way this library could make sense of.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The provider could not be reached, timed out, or reported a fault of its own. Retryable.
    /// </summary>
    Unavailable,

    /// <summary>
    /// The provider rejected the client identifier or secret.
    /// </summary>
    InvalidCredentials,

    /// <summary>
    /// The authority, or the metadata it published, cannot be used to request a token.
    /// </summary>
    InvalidConfiguration,

    /// <summary>
    /// The provider refused one of the requested scopes.
    /// </summary>
    InvalidScope
}
