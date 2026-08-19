using Microsoft.Extensions.Logging;

namespace ApricotFramework.Authentication.AspNetCore.Tests;

/// <summary>
/// Keeps the warnings, so a test can count them rather than only see that one happened.
/// </summary>
/// <typeparam name="TCategory">The category the logger is for.</typeparam>
internal sealed class RecordingLogger<TCategory> : ILogger<TCategory>
{
    public List<string> Warnings { get; } = [];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true;
    }

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        if (logLevel == LogLevel.Warning)
        {
            this.Warnings.Add(formatter(state, exception));
        }
    }
}
