namespace ApricotFramework.Authentication;

/// <summary>
/// A token could not be obtained for an outbound call.
/// </summary>
/// <remarks>
/// This is a fault of the service holding the credentials, never of whoever called it, so answering a
/// request with 401 because of one misattributes it. <see cref="Reason"/> is what a handler classifies
/// on.
/// </remarks>
public class TokenRequestException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestException"/> class.
    /// </summary>
    public TokenRequestException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestException"/> class.
    /// </summary>
    /// <param name="message">The message describing the failure.</param>
    public TokenRequestException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestException"/> class.
    /// </summary>
    /// <param name="message">The message describing the failure.</param>
    /// <param name="innerException">The underlying failure.</param>
    public TokenRequestException(string message, Exception? innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenRequestException"/> class.
    /// </summary>
    /// <param name="reason">Why the token could not be obtained.</param>
    /// <param name="message">The message describing the failure.</param>
    /// <param name="innerException">The underlying failure, if any.</param>
    public TokenRequestException(TokenRequestFailure reason, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        this.Reason = reason;
    }

    /// <summary>
    /// Gets why the token could not be obtained.
    /// </summary>
    public TokenRequestFailure Reason { get; }
}
