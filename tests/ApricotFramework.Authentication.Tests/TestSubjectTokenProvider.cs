using ApricotFramework.Authentication.TokenExchange;

namespace ApricotFramework.Authentication.Tests;

/// <summary>
/// Supplies a fixed subject, and records how often it was asked.
/// </summary>
internal sealed class TestSubjectTokenProvider(string? value, DateTimeOffset? expiresAt = null) : ISubjectTokenProvider
{
    public int Calls { get; private set; }

    public ValueTask<SubjectToken?> GetSubjectTokenAsync(CancellationToken cancellationToken = default)
    {
        this.Calls++;

        return ValueTask.FromResult(value is null ? null : new SubjectToken(value, ExpiresAt: expiresAt));
    }
}
