using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// Answers the two endpoints a provider exposes, and records what was asked of each.
/// </summary>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<RecordedRequest> requests = new();

    private readonly List<(Func<HttpRequestMessage, bool> Matches, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Respond)> routes = [];

    public IReadOnlyCollection<RecordedRequest> Requests => this.requests;

    public int CountFor(string pathFragment)
    {
        return this.requests.Count(request =>
            request.Uri.AbsoluteUri.Contains(pathFragment, StringComparison.Ordinal));
    }

    public RecordedRequest LastFor(string pathFragment)
    {
        return this.requests.Last(request =>
            request.Uri.AbsoluteUri.Contains(pathFragment, StringComparison.Ordinal));
    }

    public StubHttpMessageHandler On(string pathFragment, HttpStatusCode status, string? json = null)
    {
        return this.On(
            pathFragment,
            (_, _) => Task.FromResult(new HttpResponseMessage(status)
            {
                Content = json is null
                    ? new StringContent(string.Empty)
                    : new StringContent(json, Encoding.UTF8, "application/json"),
            }));
    }

    public StubHttpMessageHandler On(string pathFragment, HttpContent content, HttpStatusCode status = HttpStatusCode.OK)
    {
        return this.On(pathFragment, (_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = content }));
    }

    public StubHttpMessageHandler OnThrow(string pathFragment, Exception exception)
    {
        return this.On(pathFragment, (_, _) => Task.FromException<HttpResponseMessage>(exception));
    }

    public StubHttpMessageHandler On(
        string pathFragment,
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
    {
        this.routes.Add((
            request => request.RequestUri!.AbsoluteUri.Contains(pathFragment, StringComparison.Ordinal),
            respond));

        return this;
    }

    public HttpClient CreateClient()
    {
        return new HttpClient(this, disposeHandler: false);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);

        this.requests.Enqueue(new RecordedRequest(
            request.RequestUri!,
            body,
            request.Headers.Authorization?.Scheme,
            request.Headers.Authorization?.Parameter));

        // Matched in registration order, so a test can register a narrow route before a broad one.
        foreach (var route in this.routes)
        {
            if (route.Matches(request))
            {
                return await route.Respond(request, cancellationToken);
            }
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    internal sealed record RecordedRequest(Uri Uri, string? Body, string? AuthorizationScheme, string? AuthorizationParameter)
    {
        /// <summary>
        /// Parses the form body, keeping repeated keys rather than collapsing them.
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> Form()
        {
            var fields = new List<KeyValuePair<string, string>>();

            foreach (var pair in (this.Body ?? string.Empty).Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = pair.Split('=', 2);

                fields.Add(new KeyValuePair<string, string>(
                    Decode(parts[0]),
                    parts.Length > 1 ? Decode(parts[1]) : string.Empty));
            }

            return fields;
        }

        public string? Field(string name)
        {
            return this.Form()
                .Where(field => string.Equals(field.Key, name, StringComparison.Ordinal))
                .Select(field => field.Value)
                .FirstOrDefault();
        }

        public IReadOnlyList<string> Fields(string name)
        {
            return [.. this.Form()
                .Where(field => string.Equals(field.Key, name, StringComparison.Ordinal))
                .Select(field => field.Value)];
        }

        private static string Decode(string value)
        {
            return Uri.UnescapeDataString(value.Replace('+', ' '));
        }
    }
}
