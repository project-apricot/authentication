namespace ApricotFramework.Authentication;

/// <summary>
/// How client credentials are presented to the token endpoint.
/// </summary>
/// <remarks>
/// Not a preference: providers differ in which they accept, and some accept only one. RFC 6749
/// requires support for <see cref="Basic"/> and makes <see cref="PostBody"/> optional, so it is the
/// default here.
/// </remarks>
public enum ClientCredentialStyle
{
    /// <summary>
    /// An HTTP Basic <c>Authorization</c> header, per RFC 6749 section 2.3.1.
    /// </summary>
    Basic = 0,

    /// <summary>
    /// <c>client_id</c> and <c>client_secret</c> as fields in the request body.
    /// </summary>
    PostBody
}
