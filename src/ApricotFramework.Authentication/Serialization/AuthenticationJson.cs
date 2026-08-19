using System.Text.Json.Serialization;

namespace ApricotFramework.Authentication.Serialization;

/// <summary>
/// The generated readers for the two protocol documents, so no reflection is needed to parse them.
/// </summary>
[JsonSerializable(typeof(TokenEndpointResponse))]
[JsonSerializable(typeof(OpenIdProviderMetadata))]
internal sealed partial class AuthenticationJson : JsonSerializerContext
{
}
