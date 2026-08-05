// Vendored interface stubs: the minimal third-party surface the fixture
// needs, declared in-tree so the fixture compiles -- and csindex resolves its
// receivers SEMANTICALLY -- without any NuGet restore. Only shape matters;
// nothing here executes.

#pragma warning disable CS0067 // event never used

namespace StackExchange.Redis
{
    public interface IDatabase
    {
        Task<string> StringGetAsync(string key);
        Task<bool> StringSetAsync(string key, string value);
    }

    public sealed class ConnectionMultiplexer
    {
        private ConnectionMultiplexer() { }
        public static ConnectionMultiplexer Connect(string configuration) => new();
        public IDatabase GetDatabase() => null;
    }
}

namespace Confluent.Kafka
{
    public interface IProducer<TKey, TValue>
    {
        Task ProduceAsync(string topic, TValue message);
    }
}

namespace Grpc.Core
{
    public abstract class CallInvoker
    {
        public abstract Task<TResponse> AsyncUnaryCall<TRequest, TResponse>(
            string method, string host, object options, TRequest request);
    }
}

namespace RabbitMQ.Client
{
    public interface IModel
    {
        void BasicPublish(string exchange, string routingKey, object props, byte[] body);
    }
}

namespace Microsoft.Data.SqlClient
{
    public sealed class SqlConnection
    {
        public SqlConnection(string connectionString) { }
        public Task OpenAsync() => Task.CompletedTask;
    }

    public sealed class SqlCommand
    {
        public SqlCommand(string commandText, SqlConnection connection) { }
        public int CommandTimeout { get; set; }
        public Task<object> ExecuteReaderAsync() => Task.FromResult<object>(null);
    }
}

namespace Microsoft.Extensions.Logging
{
    public interface ILogger
    {
    }

    public interface ILogger<T> : ILogger
    {
    }

    public static class LoggerExtensions
    {
        public static void LogInformation(this ILogger logger, string message, params object[] args) { }
        public static void LogWarning(this ILogger logger, string message, params object[] args) { }
        public static void LogError(this ILogger logger, Exception error, string message, params object[] args) { }
    }
}

namespace Serilog
{
    public static class Log
    {
        public static void Information(string template, params object[] args) { }
        public static void Error(Exception error, string template, params object[] args) { }
    }
}

namespace Sentry
{
    public static class SentrySdk
    {
        public static void CaptureException(Exception error) { }
    }
}

namespace Microsoft.Extensions.Hosting
{
    public interface IHostedService
    {
        Task StartAsync(CancellationToken cancellationToken);
        Task StopAsync(CancellationToken cancellationToken);
    }

    public abstract class BackgroundService : IHostedService
    {
        protected abstract Task ExecuteAsync(CancellationToken stoppingToken);
        public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

namespace Microsoft.Extensions.DependencyInjection
{
    public interface IServiceCollection
    {
    }

    public static class ServiceCollectionHostedServiceExtensions
    {
        public static IServiceCollection AddHostedService<T>(this IServiceCollection services)
            where T : class => services;
    }
}

namespace Hangfire
{
    public static class RecurringJob
    {
        public static void AddOrUpdate(string recurringJobId, System.Linq.Expressions.Expression<Action> methodCall, string cronExpression) { }
    }

    public static class BackgroundJob
    {
        public static string Enqueue(System.Linq.Expressions.Expression<Action> methodCall) => "";
    }
}

namespace Microsoft.AspNetCore.Builder
{
    public sealed class WebApplication
    {
        private WebApplication() { }
        public static WebApplication Create(string[] args) => new();
        public void MapGet(string pattern, Delegate handler) { }
        public void MapPost(string pattern, Delegate handler) { }
        public void UseAuthentication() { }
        public void Run() { }
    }
}

namespace Microsoft.AspNetCore.Mvc
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class HttpGetAttribute : Attribute
    {
        public HttpGetAttribute() { }
        public HttpGetAttribute(string template) { }
    }

    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class HttpPostAttribute : Attribute
    {
        public HttpPostAttribute() { }
        public HttpPostAttribute(string template) { }
    }

    public abstract class ControllerBase
    {
    }
}
