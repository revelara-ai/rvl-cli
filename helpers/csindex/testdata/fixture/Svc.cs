// A small but realistic service exercising the G1 lane: a bounded HttpClient
// (construction-time Timeout), a deadline-less gRPC call, a Kafka produce,
// Redis, and ADO.NET command execution.

using Confluent.Kafka;
using Grpc.Core;
using Microsoft.Data.SqlClient;
using StackExchange.Redis;

namespace Fixture;

public sealed class Svc
{
    // Module-scope construction: the client and its timeout are set here,
    // away from the call sites that use them.
    private readonly HttpClient _client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    private readonly IDatabase _db = ConnectionMultiplexer.Connect("localhost:6379").GetDatabase();
    private readonly CallInvoker _invoker;
    private readonly IProducer<string, string> _producer;

    // File-scope named constant: schema v2 resolves it when passed as an argument.
    private const int DefaultLimit = 50;

    public Svc(CallInvoker invoker, IProducer<string, string> producer)
    {
        _invoker = invoker;
        _producer = producer;
    }

    /// Bounded HTTP call: the whole-call bound is the client's Timeout,
    /// visible in the construction snippet.
    public async Task<string> FetchUserAsync(string id)
    {
        var resp = await _client.GetAsync("https://api.example.com/users/" + id);
        return resp.ToString();
    }

    /// Deadline-less gRPC call: CallOptions carries no deadline, and gRPC has
    /// no default one.
    public async Task<string> SayHelloAsync(string name)
    {
        return await _invoker.AsyncUnaryCall<string, string>("SayHello", "localhost", null, name);
    }

    /// Kafka produce: librdkafka's internal retry/timeout semantics make this
    /// per-site judgment downstream.
    public async Task PublishAsync(string topic, string message)
    {
        await _producer.ProduceAsync(topic, message);
    }

    public async Task<string> CachedLookupAsync(string key)
    {
        return await _db.StringGetAsync(key);
    }

    public async Task<object> LoadAsync(string query)
    {
        var conn = new SqlConnection("Server=db;Database=app");
        await conn.OpenAsync();
        var cmd = new SqlCommand(query, conn) { CommandTimeout = DefaultLimit };
        return await cmd.ExecuteReaderAsync();
    }
}
