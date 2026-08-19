namespace ApricotFramework.Authentication.AspNetCore.Exceptions;

/// <summary>
/// A principal was required and the request carried none.
/// </summary>
/// <remarks>
/// Thrown where code has already assumed a caller is identified — past the point where the pipeline
/// would have issued a challenge. An endpoint that merely wants to know should ask instead, with
/// <c>TryGetPrincipal</c>.
/// </remarks>
public class NotAuthenticatedException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotAuthenticatedException"/> class.
    /// </summary>
    public NotAuthenticatedException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="NotAuthenticatedException"/> class.
    /// </summary>
    /// <param name="message">The message describing what was required.</param>
    public NotAuthenticatedException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="NotAuthenticatedException"/> class.
    /// </summary>
    /// <param name="message">The message describing what was required.</param>
    /// <param name="innerException">The underlying failure.</param>
    public NotAuthenticatedException(string message, Exception? innerException) : base(message, innerException)
    {
    }
}
