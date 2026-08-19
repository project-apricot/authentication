using System.Net;
using System.Text;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

/// <summary>
/// Answers a provider's two endpoints and records what was asked of each.
/// </summary>
internal sealed class RecordingHandler : HttpMessageHandler
{
    private readonly string issuer;

    public RecordingHandler(string issuer)
    {
        this.issuer = issuer.TrimEnd('/');
    }

    public List<(Uri Uri, string? Body, string? Authorization)> Requests { get; } = [];

    public (Uri Uri, string? Body, string? Authorization) TokenRequest =>
        this.Requests.Last(request => request.Uri.AbsoluteUri.Contains("/connect/token", StringComparison.Ordinal));

    /// <summary>
    /// Reads a field of the recorded form body, keeping repeats.
    /// </summary>
    public IReadOnlyList<string> Fields(string name)
    {
        var fields = new List<string>();

        foreach (var pair in (this.TokenRequest.Body ?? string.Empty).Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);

            if (string.Equals(Uri.UnescapeDataString(parts[0]), name, StringComparison.Ordinal))
            {
                fields.Add(parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace('+', ' ')) : string.Empty);
            }
        }

        return fields;
    }

    public string? Field(string name)
    {
        var fields = this.Fields(name);

        return fields.Count > 0 ? fields[0] : null;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

        this.Requests.Add((request.RequestUri!, body, request.Headers.Authorization?.Parameter));

        var json = request.RequestUri!.AbsoluteUri.Contains(".well-known", StringComparison.Ordinal)
            ? $$"""{"issuer":"{{this.issuer}}","token_endpoint":"{{this.issuer}}/connect/token"}"""
            : """{"access_token":"at-1","token_type":"Bearer","expires_in":3600}""";

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }
}
