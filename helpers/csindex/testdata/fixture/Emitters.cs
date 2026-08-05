// G4 emission surfaces: ILogger aggregates, an instrumented error path, a
// swallowing catch (the RC-027 fact), Serilog, Sentry, and an ActivitySource
// span.

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Sentry;
using Serilog;

namespace Fixture;

public sealed class Emitters
{
    private static readonly ActivitySource Source = new ActivitySource("fixture");
    private readonly ILogger<Emitters> _log;

    public Emitters(ILogger<Emitters> log)
    {
        _log = log;
    }

    /// Two log emissions in one function: ONE aggregate packet, count 2.
    public void Process(string id)
    {
        _log.LogInformation("processing {Id}", id);
        _log.LogInformation("processed {Id}", id);
    }

    /// Instrumented error path: the catch emits, so it is a capture, never a
    /// swallow.
    public void Risky()
    {
        try
        {
            throw new InvalidOperationException("boom");
        }
        catch (Exception err)
        {
            _log.LogError(err, "risky failed");
            SentrySdk.CaptureException(err);
        }
    }

    /// The swallow: neither emits nor re-throws. This is the catch_clause
    /// fact RC-027's capture-vs-swallow question needs.
    public int Swallow(string raw)
    {
        try
        {
            return int.Parse(raw);
        }
        catch
        {
            return 0;
        }
    }

    public void Audit(string user)
    {
        Log.Information("audit {User}", user);
    }

    public void Traced()
    {
        using var activity = Source.StartActivity("traced-op");
    }
}
