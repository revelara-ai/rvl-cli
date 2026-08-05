// G3 background-job surfaces: a BackgroundService implementation (the class
// declaration is the inventoried registration surface), a hosted-service
// registration, and a Hangfire recurring-job registration.

using Hangfire;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Fixture;

public sealed class Worker : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }
    }
}

public static class Jobs
{
    public static void Register(IServiceCollection services)
    {
        services.AddHostedService<Worker>();
        RecurringJob.AddOrUpdate("nightly-report", () => RunReport(), "0 2 * * *");
        BackgroundJob.Enqueue(() => RunReport());
    }

    public static void RunReport()
    {
    }
}
