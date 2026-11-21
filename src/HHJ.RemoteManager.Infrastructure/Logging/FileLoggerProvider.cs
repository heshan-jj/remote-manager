using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace HHJ.RemoteManager.Infrastructure.Logging;

/// <summary>
/// Simple thread-safe file logger + in-memory ring buffer of recent log lines so the UI Logs view
/// can display live diagnostics without reading files back from disk.
/// </summary>
public sealed class AppLogSink : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly Lock _writeGate = new();
    private readonly ConcurrentQueue<LogEntry> _recent = new();
    private readonly int _maxRecent;

    public string LogFilePath { get; }

    public event EventHandler<LogEntry>? EntryAdded;

    public AppLogSink(string logDirectory, string filePrefix = "hhj-remote-manager", int maxRecent = 500)
    {
        _maxRecent = maxRecent;
        Directory.CreateDirectory(logDirectory);
        LogFilePath = Path.Combine(logDirectory, $"{filePrefix}-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        _writer = new StreamWriter(new FileStream(LogFilePath, FileMode.Create, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(false))
        {
            AutoFlush = true,
        };
    }

    public IReadOnlyList<LogEntry> GetRecent() => [.. _recent];

    public ILogger CreateLogger(string categoryName) => new SinkLogger(this, categoryName);

    internal void Write(LogLevel level, string category, string message, Exception? exception)
    {
        var shortCategory = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;
        var entry = new LogEntry(DateTimeOffset.Now, level, shortCategory, message, exception?.ToString());

        _recent.Enqueue(entry);
        while (_recent.Count > _maxRecent && _recent.TryDequeue(out _)) { }

        var line = string.Create(CultureInfo.InvariantCulture,
            $"{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{ShortLevel(level)}] {shortCategory}: {message}");
        lock (_writeGate)
        {
            _writer.WriteLine(line);
            if (exception is not null) _writer.WriteLine(exception);
        }

        EntryAdded?.Invoke(this, entry);
    }

    private static string ShortLevel(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "LOG",
    };

    public void Dispose()
    {
        lock (_writeGate) _writer.Dispose();
    }

    private sealed class SinkLogger(AppLogSink sink, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            sink.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Category, string Message, string? ExceptionText);
