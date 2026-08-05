// csindex -- C# retriever helper for rvlscan.
//
// Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
// This is the C# sibling of helpers/goindex, helpers/pyindex, and
// helpers/tsindex. It emits the SAME versioned packet stream rvlscan
// consumes, for C# source instead of Go/Python/TypeScript.
//
// The split this enforces
//
//   Per-language work is RETRIEVAL: mechanical, semantically neutral, no
//   reliability opinion. "Here is the call site." "Here is the client this
//   receiver was constructed from." That is compiler-frontend work and it is
//   genuinely cheap to add per language.
//
//   JUDGEMENT stays semantic -- the LLM panel now, a distilled student later.
//   Nothing here decides whether a call is bounded, retried, or safe. It only
//   reports what exists and where, and how confident the resolution was.
//
// Engine: Roslyn (Microsoft.CodeAnalysis), syntax trees PLUS a semantic
// model. The compilation is AD HOC -- every discovered .cs file plus the
// trusted platform assemblies of the running runtime -- never an MSBuild
// project load, so csindex needs no NuGet restore of the TARGET repository
// and cannot be wedged by a non-loading project. The price is honest
// degradation: a receiver whose type lives in an unrestored package does not
// resolve semantically. Then:
//
//   - a STRONG I/O verb still emits the site, with client_type taken from
//     syntactic construction tracking when available (resolved=false, the
//     low-confidence tier -- the panel discounts, downstream specs abstain);
//   - a WEAK verb (Get/Send/Read/... -- names that collide with non-I/O
//     surfaces) abstains by omission unless the receiver RESOLVED
//     semantically. No heuristic tier ever invents an identity.

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Csindex;

internal static class Program
{
    // PACKET_SCHEMA is the version of the emitted packet contract. rvlscan
    // absorbs helper churn behind this number: a consumer that does not know
    // a version refuses the stream rather than guessing at its shape. It MUST
    // agree with goindex's PacketSchema, pyindex's PACKET_SCHEMA, tsindex's
    // PACKET_SCHEMA, and rvl_core::PACKET_SCHEMA.
    private const int PacketSchema = 2;

    // Byte cap per emitted snippet, mirroring goindex's maxSnippetBytes.
    private const int MaxSnippetBytes = 2400;

    // Construction snippets to include per site (mirrors goindex).
    private const int MaxCtorsEmitted = 2;

    private static int Main(string[] args)
    {
        bool packetSchema = false, retrieve = false;
        string root = ".", name = null, files = "";
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--packet-schema": packetSchema = true; break;
                case "--retrieve": retrieve = true; break;
                case "--root": root = Next(args, ref i); break;
                case "--name": name = Next(args, ref i); break;
                case "--files": files = Next(args, ref i); break;
                default:
                    Console.Error.WriteLine($"csindex: unknown argument {args[i]}");
                    return 2;
            }
        }

        // Lets a consumer negotiate the contract before paying for a load.
        if (packetSchema)
        {
            Console.WriteLine(PacketSchema);
            return 0;
        }

        if (retrieve)
        {
            var absRoot = Path.GetFullPath(root);
            var snapshot = name ?? Path.GetFileName(absRoot.TrimEnd(Path.DirectorySeparatorChar));
            if (string.IsNullOrEmpty(snapshot)) snapshot = absRoot;
            var records = Retriever.Run(absRoot, snapshot, files);
            Emit(records);
            Console.Error.WriteLine($"{snapshot}: {records.Count} retrieved sites");
            return 0;
        }

        Console.Error.WriteLine(
            "usage: csindex --packet-schema | --retrieve --root <dir> [--name <snapshot>] [--files a,b]");
        return 2;
    }

    private static string Next(string[] args, ref int i)
    {
        if (i + 1 >= args.Length)
        {
            Console.Error.WriteLine($"csindex: {args[i]} needs a value");
            Environment.Exit(2);
        }
        return args[++i];
    }

    /// Stamp schema + site_key on every record and write one JSON object per
    /// line. One choke point: a record that reaches a consumer unstamped is a
    /// record no index can key. Written synchronously so process exit can
    /// never truncate the stream (the tsindex stdout lesson, po-3t3oj.37).
    private static void Emit(List<Packet> records)
    {
        var opts = new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.Never };
        var stdout = Console.Out;
        foreach (var rec in records)
        {
            rec.PacketSchemaVersion = PacketSchema;
            // Mirror rvl_index::site_key and goindex's siteKey exactly:
            // file:line:client_type:method. A file:line is NOT unique --
            // several client calls can share a line -- so downstream joins
            // key on this.
            rec.SiteKey = $"{rec.FilePath}:{rec.LineNumber}:{rec.ClientType}:{rec.Func}";
            stdout.WriteLine(JsonSerializer.Serialize(rec, opts));
        }
        stdout.Flush();
    }
}

// ---------------------------------------------------------------------------
// Packet contract (field-for-field with goindex/pyindex/tsindex).
// ---------------------------------------------------------------------------

internal sealed class Packet
{
    [JsonPropertyName("packet_schema")] public int PacketSchemaVersion { get; set; }
    [JsonPropertyName("site_key")] public string SiteKey { get; set; } = "";
    [JsonPropertyName("snapshot_id")] public string SnapshotId { get; set; } = "";
    [JsonPropertyName("file_path")] public string FilePath { get; set; } = "";
    [JsonPropertyName("line_number")] public int LineNumber { get; set; }
    [JsonPropertyName("symbol")] public string Symbol { get; set; } = "";
    [JsonPropertyName("func")] public string Func { get; set; } = "";
    [JsonPropertyName("receiver")] public string Receiver { get; set; } = "";
    [JsonPropertyName("client_type")] public string ClientType { get; set; } = "";
    [JsonPropertyName("snippet")] public string Snippet { get; set; } = "";
    [JsonPropertyName("enclosing_function_body")] public string EnclosingFunctionBody { get; set; } = "";
    [JsonPropertyName("callers")] public List<object> Callers { get; set; } = new();
    [JsonPropertyName("callees")] public List<object> Callees { get; set; } = new();
    [JsonPropertyName("client_construction")] public List<Ctor> ClientConstruction { get; set; } = new();
    [JsonPropertyName("const_args")] public List<ConstArg> ConstArgs { get; set; } = new();
    [JsonPropertyName("macro_expansion")] public bool MacroExpansion { get; set; }
    [JsonPropertyName("site_kind")] public string SiteKind { get; set; } = "";
    [JsonPropertyName("provenance")] public Provenance Prov { get; set; } = new();
    [JsonPropertyName("lang")] public string Lang { get; set; } = "csharp";
}

internal sealed class Ctor
{
    [JsonPropertyName("file")] public string File { get; set; } = "";
    [JsonPropertyName("line")] public int Line { get; set; }
    [JsonPropertyName("symbol")] public string Symbol { get; set; } = "";
    [JsonPropertyName("source")] public string Source { get; set; } = "";
}

internal sealed class ConstArg
{
    [JsonPropertyName("index")] public int Index { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
    [JsonPropertyName("how")] public string How { get; set; } = "";
}

internal sealed class Provenance
{
    [JsonPropertyName("client_type_resolved")] public bool ClientTypeResolved { get; set; }
    [JsonPropertyName("callers_total")] public int CallersTotal { get; set; }
    [JsonPropertyName("callers_included")] public int CallersIncluded { get; set; }
    [JsonPropertyName("callees_total")] public int CalleesTotal { get; set; }
    [JsonPropertyName("callees_included")] public int CalleesIncluded { get; set; }
}

// ---------------------------------------------------------------------------
// Retrieval
// ---------------------------------------------------------------------------

internal static class Retriever
{
    // Mirrors rvl_core's site-kind constants.
    private const string SiteKindServerEntry = "server_entry";
    private const string SiteKindBackgroundJob = "background_job";
    private const string SiteKindEmission = "emission_point";

    // -- G1 client-call selection tables -------------------------------------
    //
    // Two tiers by how likely the method name is to also be an ordinary
    // non-I/O surface (the pyindex STRONG/WEAK model):
    //
    //   Strong -- verbs that are almost never anything but an I/O call
    //     (SendAsync, ExecuteReaderAsync, ProduceAsync, ...). Emitted whether
    //     or not the receiver type resolved: an unresolved
    //     `cmd.ExecuteReaderAsync()` is still a real DB call site, it just
    //     lands as a low-confidence tier.
    //
    //   Weak -- verbs that collide with local/non-I/O methods (Get, Send,
    //     Read, Run, ...). Emitted ONLY when the receiver RESOLVED through
    //     the semantic model, so `_dict.Get(k)` noise is dropped.

    private static readonly HashSet<string> StrongIoMethods = new()
    {
        // HttpClient family
        "SendAsync", "GetAsync", "PostAsync", "PutAsync", "PatchAsync", "DeleteAsync",
        "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync",
        "GetFromJsonAsync", "PostAsJsonAsync", "PutAsJsonAsync",
        // ADO.NET / Dapper-adjacent command execution
        "ExecuteReader", "ExecuteReaderAsync", "ExecuteNonQuery", "ExecuteNonQueryAsync",
        "ExecuteScalar", "ExecuteScalarAsync",
        // EF Core unit-of-work + materializing LINQ terminals
        "SaveChanges", "SaveChangesAsync",
        "ToListAsync", "FirstOrDefaultAsync", "SingleOrDefaultAsync", "AnyAsync", "CountAsync",
        // StackExchange.Redis
        "StringGet", "StringSet", "StringGetAsync", "StringSetAsync",
        "HashGetAsync", "HashSetAsync", "KeyDeleteAsync",
        // Kafka / messaging
        "Produce", "ProduceAsync", "Consume",
        // RabbitMQ
        "BasicPublish", "BasicConsume", "BasicGet",
        // gRPC core invocation surface
        "AsyncUnaryCall", "BlockingUnaryCall", "AsyncServerStreamingCall",
        "AsyncClientStreamingCall", "AsyncDuplexStreamingCall",
        // connections / sockets
        "OpenAsync", "ConnectAsync", "ReceiveAsync", "SendMailAsync",
    };

    private static readonly HashSet<string> WeakIoMethods = new()
    {
        "Get", "Send", "Read", "ReadAsync", "Write", "WriteAsync",
        "Query", "QueryAsync", "Execute", "ExecuteAsync",
        "Run", "Invoke", "InvokeAsync", "Call", "Connect",
    };

    // -- G2 server-entry tables ---------------------------------------------
    //
    // Emitted only when the receiver RESOLVES to a known hosting surface --
    // an unresolved `app.MapGet(...)` could as easily be a local builder, so
    // it abstains from this lane rather than guessing.

    private static readonly HashSet<string> ServerTypes = new()
    {
        "Microsoft.AspNetCore.Builder.WebApplication",
        "Microsoft.AspNetCore.Builder.IApplicationBuilder",
        "Microsoft.AspNetCore.Routing.IEndpointRouteBuilder",
    };

    private static readonly HashSet<string> ServerRouteMethods = new()
    {
        "MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch",
        "Map", "MapMethods", "MapFallback", "MapControllers", "MapHub", "MapGrpcService",
    };

    // Middleware attachment is matched by the `Use` prefix on an already
    // RESOLVED hosting surface (UseAuthentication, UseCors, UseMiddleware,
    // ...): on WebApplication/IApplicationBuilder that prefix IS the
    // middleware convention, and the receiver-resolution gate keeps a local
    // builder's UseSomething out. No allowlist to fall behind the framework.

    // MVC controller attributes that register the decorated action as a
    // server entry. Matched by the attribute's RESOLVED containing type.
    private static readonly HashSet<string> MvcRouteAttributes = new()
    {
        "Microsoft.AspNetCore.Mvc.HttpGetAttribute",
        "Microsoft.AspNetCore.Mvc.HttpPostAttribute",
        "Microsoft.AspNetCore.Mvc.HttpPutAttribute",
        "Microsoft.AspNetCore.Mvc.HttpDeleteAttribute",
        "Microsoft.AspNetCore.Mvc.HttpPatchAttribute",
        "Microsoft.AspNetCore.Mvc.HttpHeadAttribute",
        "Microsoft.AspNetCore.Mvc.HttpOptionsAttribute",
        "Microsoft.AspNetCore.Mvc.RouteAttribute",
    };

    // -- G3 background-job tables -------------------------------------------
    //
    // Registration/dispatch methods on a RESOLVED framework identity. Like
    // every table here this selects what to surface; whether a registration
    // needs a bound is spec knowledge downstream (ApiSpec.site_kinds).

    private static readonly Dictionary<string, HashSet<string>> JobCallMethods = new()
    {
        ["Microsoft.Extensions.DependencyInjection.IServiceCollection"] = new() { "AddHostedService" },
        ["Hangfire.RecurringJob"] = new() { "AddOrUpdate" },
        ["Hangfire.BackgroundJob"] = new() { "Enqueue", "Schedule", "ContinueJobWith" },
        ["Quartz.IScheduler"] = new() { "ScheduleJob" },
    };

    // Base types / interfaces whose subclasses ARE background work: the class
    // declaration is the registration surface this lane inventories.
    private const string BackgroundServiceType = "Microsoft.Extensions.Hosting.BackgroundService";
    private const string HostedServiceInterface = "Microsoft.Extensions.Hosting.IHostedService";

    // -- G4 emission tables --------------------------------------------------
    //
    // (identity, category) per resolved receiver; the emit-verb allowlists
    // keep non-emitting surface (LoggerFactory.Create, SentrySdk.Init) out.
    // VOLUME CONTROL is the load-bearing constraint: emission packets are
    // AGGREGATES -- one per (enclosing function, framework identity,
    // category) -- never one packet per log line.

    private static readonly HashSet<string> IloggerMethods = new()
    {
        "Log", "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
    };

    private static readonly HashSet<string> SerilogMethods = new()
    {
        "Verbose", "Debug", "Information", "Warning", "Error", "Fatal", "Write",
    };

    private static readonly HashSet<string> SentryMethods = new()
    {
        "CaptureException", "CaptureMessage", "CaptureEvent",
    };

    // Error-level log verbs: a log emission ON an error path is the capture
    // fact RC-027 asks about, so these shift category log -> error_capture
    // when the call sits inside a catch clause.
    private static readonly HashSet<string> ErrorLevelLogMethods = new()
    {
        "LogError", "LogCritical", "Error", "Fatal",
    };

    private static readonly HashSet<string> SkipDirs = new()
    {
        ".git", "bin", "obj", "node_modules", "packages", ".vs", "TestResults", "artifacts",
    };

    public static List<Packet> Run(string root, string snapshot, string filesArg)
    {
        // Discover every .cs file (the whole tree feeds the semantic model
        // even when --files narrows what is EMITTED, so an incremental reload
        // still resolves receivers declared in unchanged files).
        var all = Discover(root).ToList();
        var emitOnly = ParseFilesArg(root, filesArg);

        var trees = new List<SyntaxTree>();
        var pathOf = new Dictionary<SyntaxTree, (string Abs, string Rel)>();
        foreach (var (abs, rel) in all)
        {
            string text;
            try
            {
                text = File.ReadAllText(abs);
            }
            catch (Exception err)
            {
                Console.Error.WriteLine($"skip {rel}: {err.Message}");
                continue;
            }
            var tree = CSharpSyntaxTree.ParseText(SourceText.From(text), path: abs);
            trees.Add(tree);
            pathOf[tree] = (abs, rel);
        }

        var compilation = CSharpCompilation.Create(
            "csindex-adhoc",
            trees,
            PlatformReferences(),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var records = new List<Packet>();
        foreach (var tree in trees)
        {
            var (_, rel) = pathOf[tree];
            if (emitOnly != null && !emitOnly.Contains(rel)) continue;
            try
            {
                records.AddRange(RetrieveTree(tree, compilation.GetSemanticModel(tree), rel, snapshot));
            }
            catch (Exception err)
            {
                // Honest degradation: a file the walker cannot process is a
                // logged skip, never a silent hole or a guessed packet.
                Console.Error.WriteLine($"retrieve failed {rel}: {err.Message}");
            }
        }
        return records;
    }

    /// Metadata references for the RUNNING runtime's trusted platform
    /// assemblies. This resolves the BCL (HttpClient, ActivitySource, ...)
    /// and anything compiled into the target tree itself (vendored stubs);
    /// unrestored NuGet package types deliberately stay unresolved -- that is
    /// the degradation contract, not a bug to paper over.
    private static List<MetadataReference> PlatformReferences()
    {
        var refs = new List<MetadataReference>();
        if (AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") is string tpa)
        {
            foreach (var p in tpa.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    refs.Add(MetadataReference.CreateFromFile(p));
                }
                catch
                {
                    // an unloadable platform assembly just narrows resolution
                }
            }
        }
        return refs;
    }

    private static IEnumerable<(string Abs, string Rel)> Discover(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            string[] entries;
            try
            {
                // Eager: a permission error surfaces HERE (a logged-by-omission
                // skip), never mid-yield where the try cannot cover it.
                entries = Directory.GetFileSystemEntries(dir);
            }
            catch
            {
                continue;
            }
            foreach (var entry in entries.OrderBy(e => e, StringComparer.Ordinal))
            {
                if (Directory.Exists(entry))
                {
                    if (!SkipDirs.Contains(Path.GetFileName(entry))) stack.Push(entry);
                }
                else if (entry.EndsWith(".cs", StringComparison.Ordinal))
                {
                    yield return (entry, Rel(root, entry));
                }
            }
        }
    }

    private static string Rel(string root, string abs) =>
        Path.GetRelativePath(root, abs).Replace(Path.DirectorySeparatorChar, '/');

    /// With --files, only the listed (repo-relative) .cs files are EMITTED --
    /// the incremental reload path. Matching is exact-path, never a prefix.
    private static HashSet<string> ParseFilesArg(string root, string filesArg)
    {
        if (string.IsNullOrWhiteSpace(filesArg)) return null;
        var set = new HashSet<string>();
        foreach (var raw in filesArg.Split(','))
        {
            var nameArg = raw.Trim();
            if (nameArg.Length == 0) continue;
            var abs = Path.IsPathRooted(nameArg) ? nameArg : Path.Combine(root, nameArg);
            set.Add(Rel(root, Path.GetFullPath(abs)));
        }
        return set;
    }

    // -- per-file retrieval --------------------------------------------------

    private static List<Packet> RetrieveTree(SyntaxTree tree, SemanticModel model, string filePath, string snapshot)
    {
        var rootNode = tree.GetRoot();
        var index = new FileIndex(filePath, rootNode);
        var outRecords = new List<Packet>();

        // G2b pre-pass: controller attributes register the DECORATED action.
        foreach (var method in rootNode.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            foreach (var attr in method.AttributeLists.SelectMany(l => l.Attributes))
            {
                var attrType = model.GetSymbolInfo(attr).Symbol?.ContainingType;
                if (attrType == null) continue;
                var identity = Identity(attrType);
                if (!MvcRouteAttributes.Contains(identity)) continue;
                var verb = attrType.Name.EndsWith("Attribute", StringComparison.Ordinal)
                    ? attrType.Name[..^"Attribute".Length]
                    : attrType.Name;
                var rec = NewPacket(snapshot, filePath, Line(attr), method.Identifier.ValueText,
                    verb, "", "Microsoft.AspNetCore.Mvc", Cap("[" + attr + "]"), Cap(method.ToString()));
                rec.SiteKind = SiteKindServerEntry;
                rec.Prov.ClientTypeResolved = true;
                rec.ConstArgs = AttrConstArgs(attr);
                outRecords.Add(rec);
            }
        }

        // G3b: a BackgroundService / IHostedService implementation IS
        // background work; the class declaration is the inventoried surface.
        foreach (var cls in rootNode.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var sym = model.GetDeclaredSymbol(cls);
            if (sym == null) continue;
            var baseIdentity = HostedIdentity(sym);
            if (baseIdentity == null) continue;
            var exec = cls.Members.OfType<MethodDeclarationSyntax>()
                .FirstOrDefault(m => m.Identifier.ValueText is "ExecuteAsync" or "StartAsync");
            var rec = NewPacket(snapshot, filePath, Line(cls), cls.Identifier.ValueText,
                exec?.Identifier.ValueText ?? "ExecuteAsync", "", baseIdentity,
                Cap($"class {cls.Identifier.ValueText} : {cls.BaseList}"),
                exec != null ? Cap(exec.ToString()) : "");
            rec.SiteKind = SiteKindBackgroundJob;
            rec.Prov.ClientTypeResolved = true;
            outRecords.Add(rec);
        }

        // Main invocation walk: G2 call-form > G3 > G4 (aggregated) > G1.
        var emissions = new EmissionCollector(filePath, rootNode);
        foreach (var inv in rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (inv.Expression is not MemberAccessExpressionSyntax ma) continue;
            var method = ma.Name.Identifier.ValueText;
            var receiverExpr = ma.Expression;
            var receiverText = receiverExpr.ToString();
            var (clientType, resolved) = ResolveReceiver(model, receiverExpr, index);
            var enclosing = EnclosingFunction(inv);

            // G2 call-form registrations, checked BEFORE the G1 gate so a
            // registration never emits as a client call.
            if (resolved && ServerTypes.Contains(clientType)
                && (ServerRouteMethods.Contains(method)
                    || method.StartsWith("Use", StringComparison.Ordinal)))
            {
                var rec = NewPacket(snapshot, filePath, Line(inv), enclosing.Name, method,
                    receiverText, clientType, Cap(inv.ToString()), enclosing.Body);
                rec.SiteKind = SiteKindServerEntry;
                rec.Prov.ClientTypeResolved = true;
                rec.ConstArgs = ConstArgs(inv, index);
                outRecords.Add(rec);
                continue;
            }

            // G3 registrations/dispatches on a resolved framework identity.
            if (resolved && JobCallMethods.TryGetValue(clientType, out var jobMethods)
                && jobMethods.Contains(method))
            {
                var rec = NewPacket(snapshot, filePath, Line(inv), enclosing.Name, method,
                    receiverText, clientType, Cap(inv.ToString()), enclosing.Body);
                rec.SiteKind = SiteKindBackgroundJob;
                rec.Prov.ClientTypeResolved = true;
                rec.ConstArgs = ConstArgs(inv, index);
                outRecords.Add(rec);
                continue;
            }

            // G4 emissions ride their own aggregates, never the G1 stream.
            if (resolved && emissions.Offer(inv, method, clientType, enclosing.Name))
            {
                continue;
            }
            if (!resolved)
            {
                // An emission-shaped call whose receiver did NOT resolve
                // still suppresses the swallow claim for its catch clause:
                // fail toward abstain, never toward accusing an error path
                // that plausibly logs through an unrestored package's logger.
                emissions.NoteUnresolvedEmissionShape(inv, method);
            }

            // G1 gate: strong verbs always; weak verbs only when resolved.
            var isStrong = StrongIoMethods.Contains(method);
            if (!isStrong && !(WeakIoMethods.Contains(method) && resolved)) continue;

            var g1 = NewPacket(snapshot, filePath, Line(inv), enclosing.Name, method,
                receiverText, clientType, Cap(inv.ToString()), enclosing.Body);
            g1.Prov.ClientTypeResolved = resolved;
            g1.ConstArgs = ConstArgs(inv, index);
            g1.ClientConstruction = index.ConstructionsFor(receiverText, clientType);
            outRecords.Add(g1);
        }

        outRecords.AddRange(emissions.Records(snapshot));
        return outRecords;
    }

    // -- receiver resolution -------------------------------------------------

    /// (client_type, resolved). Semantic model first: an instance receiver's
    /// type, or the type itself for a static-class receiver
    /// (RecurringJob.AddOrUpdate). When the model cannot resolve (unrestored
    /// package), fall back to this file's syntactic construction tracking --
    /// the client_type is then whatever the source wrote, and resolved stays
    /// FALSE: evidence attached, confidence not claimed.
    private static (string ClientType, bool Resolved) ResolveReceiver(
        SemanticModel model, ExpressionSyntax receiver, FileIndex index)
    {
        var symbol = model.GetSymbolInfo(receiver).Symbol;
        if (symbol is INamedTypeSymbol staticType && staticType.TypeKind != TypeKind.Error)
        {
            return (Identity(staticType), true);
        }
        var type = model.GetTypeInfo(receiver).Type;
        if (type != null && type.TypeKind != TypeKind.Error)
        {
            return (Identity(type), true);
        }
        var tracked = index.TrackedType(receiver.ToString());
        return (tracked ?? "", false);
    }

    /// Canonical identity: containing namespace + bare type name, generic
    /// arity stripped ("Confluent.Kafka.IProducer", never IProducer<K,V>).
    /// ILogger<T> normalizes to the ILogger identity the spec corpus keys on.
    private static string Identity(ITypeSymbol type)
    {
        if (type is INamedTypeSymbol named)
        {
            var ns = named.ContainingNamespace;
            var name = named.Name;
            if (ns == null || ns.IsGlobalNamespace) return name;
            return ns.ToDisplayString() + "." + name;
        }
        return type.ToDisplayString();
    }

    /// The hosted-work identity a class registers under, or null. Walks the
    /// base-type chain for BackgroundService and the interface set for
    /// IHostedService -- both resolved semantically, never by name match.
    private static string HostedIdentity(INamedTypeSymbol cls)
    {
        for (var b = cls.BaseType; b != null; b = b.BaseType)
        {
            if (Identity(b) == BackgroundServiceType) return BackgroundServiceType;
        }
        foreach (var i in cls.AllInterfaces)
        {
            if (Identity(i) == HostedServiceInterface) return HostedServiceInterface;
        }
        return null;
    }

    // -- packets, snippets, arguments ---------------------------------------

    private static Packet NewPacket(string snapshot, string filePath, int line, string symbol,
        string func, string receiver, string clientType, string snippet, string body)
    {
        return new Packet
        {
            SnapshotId = snapshot,
            FilePath = filePath,
            LineNumber = line,
            Symbol = symbol,
            Func = func,
            Receiver = receiver,
            ClientType = clientType,
            Snippet = snippet,
            EnclosingFunctionBody = body,
        };
    }

    private static int Line(SyntaxNode node) =>
        node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

    private static string Cap(string text)
    {
        if (text == null) return "";
        if (text.Length > MaxSnippetBytes) return text[..MaxSnippetBytes] + "\n// ... truncated";
        return text;
    }

    private sealed record Enclosing(string Name, string Body);

    private static Enclosing EnclosingFunction(SyntaxNode node)
    {
        foreach (var anc in node.Ancestors())
        {
            switch (anc)
            {
                case LocalFunctionStatementSyntax lf:
                    return new Enclosing(lf.Identifier.ValueText, Cap(lf.ToString()));
                case MethodDeclarationSyntax m:
                    return new Enclosing(m.Identifier.ValueText, Cap(m.ToString()));
                case ConstructorDeclarationSyntax c:
                    return new Enclosing(c.Identifier.ValueText, Cap(c.ToString()));
            }
        }
        return new Enclosing("", "");
    }

    /// Constant-valued arguments at the call site (schema v2). Literal tokens
    /// report as "literal"; identifiers resolved through the file's `const`
    /// declarations report as "named_constant". `index` is the zero-based
    /// position as written; `name` is the argument's name for named arguments
    /// (`timeout: 5`), "" for positional ones. Retrieval only: no deep
    /// constant propagation, no opinion about what a value means.
    private static List<ConstArg> ConstArgs(InvocationExpressionSyntax inv, FileIndex index)
    {
        var outArgs = new List<ConstArg>();
        var args = inv.ArgumentList?.Arguments;
        if (args == null) return outArgs;
        for (int i = 0; i < args.Value.Count; i++)
        {
            var a = args.Value[i];
            var argName = a.NameColon?.Name.Identifier.ValueText ?? "";
            string value = null, how = null;
            switch (a.Expression)
            {
                case LiteralExpressionSyntax lit:
                    value = lit.Token.Text;
                    how = "literal";
                    break;
                case IdentifierNameSyntax id when index.ConstValue(id.Identifier.ValueText) is string c:
                    value = c;
                    how = "named_constant";
                    break;
            }
            if (how != null)
            {
                outArgs.Add(new ConstArg { Index = i, Name = argName, Value = value, How = how });
            }
        }
        return outArgs;
    }

    /// Constant arguments of an MVC route attribute ([HttpGet("/users")]):
    /// the route template literal rides the same const_args machinery.
    private static List<ConstArg> AttrConstArgs(AttributeSyntax attr)
    {
        var outArgs = new List<ConstArg>();
        var args = attr.ArgumentList?.Arguments;
        if (args == null) return outArgs;
        for (int i = 0; i < args.Value.Count; i++)
        {
            if (args.Value[i].Expression is LiteralExpressionSyntax lit)
            {
                outArgs.Add(new ConstArg { Index = i, Name = "", Value = lit.Token.Text, How = "literal" });
            }
        }
        return outArgs;
    }

    // -- G4 aggregation ------------------------------------------------------

    private sealed class EmissionCollector
    {
        private readonly string _filePath;
        private readonly List<CatchClauseSyntax> _catches;
        private readonly bool[] _catchEmits;
        private readonly bool[] _catchRethrows;
        private sealed class Agg
        {
            public int Line;
            public string Method;
            public string Snippet;
            public int Count;
        }
        private readonly Dictionary<(string Symbol, string Framework, string Category), Agg> _aggs = new();

        public EmissionCollector(string filePath, SyntaxNode root)
        {
            _filePath = filePath;
            _catches = root.DescendantNodes().OfType<CatchClauseSyntax>().ToList();
            _catchEmits = new bool[_catches.Count];
            _catchRethrows = new bool[_catches.Count];
            for (int i = 0; i < _catches.Count; i++)
            {
                _catchRethrows[i] = _catches[i].Block != null
                    && _catches[i].Block.DescendantNodes().OfType<ThrowStatementSyntax>().Any();
            }
        }

        /// (framework identity, category) for a RESOLVED receiver identity,
        /// or null when the call is not a recognized emission.
        private static (string Framework, string Category)? EmissionIdentity(string clientType, string method)
        {
            switch (clientType)
            {
                case "Microsoft.Extensions.Logging.ILogger" when IloggerMethods.Contains(method):
                    return ("Microsoft.Extensions.Logging.ILogger", "log");
                case "Serilog.Log" when SerilogMethods.Contains(method):
                case "Serilog.ILogger" when SerilogMethods.Contains(method):
                    return ("Serilog.Log", "log");
                case "Sentry.SentrySdk" when SentryMethods.Contains(method):
                    return ("Sentry.SentrySdk", "error_capture");
                case "System.Diagnostics.ActivitySource" when method == "StartActivity":
                    return ("System.Diagnostics.ActivitySource", "trace");
                default:
                    return null;
            }
        }

        /// Record the call as an emission if it is one. Returns whether it
        /// was consumed (and must stay out of the G1 stream).
        public bool Offer(InvocationExpressionSyntax inv, string method, string clientType, string symbol)
        {
            var hit = EmissionIdentity(clientType, method);
            if (hit == null) return false;
            var (framework, category) = hit.Value;
            var inCatch = ContainingCatch(inv);
            if (inCatch >= 0)
            {
                _catchEmits[inCatch] = true;
                if (category == "log" && ErrorLevelLogMethods.Contains(method))
                {
                    // A log emission ON an error path is the capture fact.
                    category = "error_capture";
                }
            }
            var key = (symbol, framework, category);
            if (!_aggs.TryGetValue(key, out var agg))
            {
                _aggs[key] = agg = new Agg
                {
                    Line = Line(inv),
                    Method = method,
                    Snippet = Cap(inv.ToString()),
                };
            }
            agg.Count++;
            return true;
        }

        /// Degradation guard: a call whose METHOD NAME is an emission verb but
        /// whose receiver did not resolve marks its catch as "not provably a
        /// swallow" without emitting any aggregate. The swallow fact is an
        /// accusation; absence of resolution weakens it to an abstention.
        public void NoteUnresolvedEmissionShape(InvocationExpressionSyntax inv, string method)
        {
            if (!IloggerMethods.Contains(method) && !SerilogMethods.Contains(method)
                && !SentryMethods.Contains(method) && method != "StartActivity")
            {
                return;
            }
            var inCatch = ContainingCatch(inv);
            if (inCatch >= 0) _catchEmits[inCatch] = true;
        }

        private int ContainingCatch(SyntaxNode node)
        {
            for (int i = 0; i < _catches.Count; i++)
            {
                if (_catches[i].Block != null && _catches[i].Block.Span.Contains(node.Span)) return i;
            }
            return -1;
        }

        /// The file's emission aggregates, plus the SWALLOW fact RC-027's
        /// capture-vs-swallow question needs: a catch that neither emits
        /// anything recognized nor re-throws, aggregated per function under
        /// the `catch_clause` identity (the tsindex convention).
        public List<Packet> Records(string snapshot)
        {
            for (int i = 0; i < _catches.Count; i++)
            {
                if (_catchEmits[i] || _catchRethrows[i]) continue;
                var symbol = EnclosingFunction(_catches[i]).Name;
                var key = (symbol, "catch_clause", "error_capture");
                if (!_aggs.TryGetValue(key, out var agg))
                {
                    _aggs[key] = agg = new Agg { Line = Line(_catches[i]), Method = "catch", Snippet = "" };
                }
                agg.Count++;
            }

            var outRecords = new List<Packet>();
            foreach (var kv in _aggs.OrderBy(kv => kv.Value.Line))
            {
                var (symbol, framework, category) = kv.Key;
                var agg = kv.Value;
                var rec = new Packet
                {
                    SnapshotId = snapshot,
                    FilePath = _filePath,
                    LineNumber = agg.Line,
                    Symbol = symbol,
                    Func = agg.Method,
                    ClientType = framework,
                    Snippet = agg.Snippet,
                    // Volume control: no function body on aggregates.
                    EnclosingFunctionBody = "",
                    SiteKind = SiteKindEmission,
                    ConstArgs = new List<ConstArg>
                    {
                        new() { Index = 0, Name = "emission_category", Value = category, How = "aggregate" },
                        new() { Index = 0, Name = "emission_count", Value = agg.Count.ToString(), How = "aggregate" },
                    },
                };
                rec.Prov.ClientTypeResolved = framework != "catch_clause";
                outRecords.Add(rec);
            }
            return outRecords;
        }
    }

    // -- per-file syntactic tracking (the no-semantic fallback tier) ---------

    /// Construction and constant tracking for one file. Everything is
    /// best-effort and file-scoped (no real name scoping): a later assignment
    /// shadows an earlier one, last write wins -- the same recorded
    /// unsoundness pyindex carries, cheaper than a control-flow graph. The
    /// panel sees the confidence via client_type_resolved and discounts.
    private sealed class FileIndex
    {
        // receiver text ("client", "_client", "this._client") -> written type text
        private readonly Dictionary<string, string> _trackedTypes = new();
        // receiver text -> construction snippets
        private readonly Dictionary<string, List<Ctor>> _ctorsByName = new();
        // written type text -> construction snippets
        private readonly Dictionary<string, List<Ctor>> _ctorsByType = new();
        // const NAME -> literal token text
        private readonly Dictionary<string, string> _consts = new();

        public FileIndex(string filePath, SyntaxNode root)
        {
            foreach (var decl in root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
            {
                var isConst = decl.Modifiers.Any(m => m.IsKind(SyntaxKind.ConstKeyword));
                foreach (var v in decl.Declaration.Variables)
                {
                    Track(filePath, v.Identifier.ValueText, v.Initializer?.Value, decl, isConst);
                }
            }
            foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
            {
                var isConst = field.Modifiers.Any(m => m.IsKind(SyntaxKind.ConstKeyword));
                foreach (var v in field.Declaration.Variables)
                {
                    Track(filePath, v.Identifier.ValueText, v.Initializer?.Value, field, isConst);
                }
            }
            foreach (var assign in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                if (assign.Left is IdentifierNameSyntax or MemberAccessExpressionSyntax)
                {
                    var stmt = assign.Ancestors().OfType<StatementSyntax>().FirstOrDefault() ?? (SyntaxNode)assign;
                    Track(filePath, assign.Left.ToString(), assign.Right, stmt, isConst: false);
                }
            }
        }

        private void Track(string filePath, string boundName, ExpressionSyntax value, SyntaxNode statement, bool isConst)
        {
            switch (value)
            {
                case LiteralExpressionSyntax lit when isConst:
                    _consts[boundName] = lit.Token.Text;
                    break;
                case ObjectCreationExpressionSyntax ctor:
                    var typeText = ctor.Type.ToString();
                    var snip = new Ctor
                    {
                        File = filePath,
                        Line = Line(statement),
                        Symbol = typeText,
                        Source = Cap(statement.ToString()),
                    };
                    _trackedTypes[boundName] = typeText;
                    // "this._c" and "_c" name the same field in practice.
                    var bare = boundName.StartsWith("this.", StringComparison.Ordinal)
                        ? boundName["this.".Length..]
                        : boundName;
                    AddSnip(_ctorsByName, boundName, snip);
                    if (bare != boundName) AddSnip(_ctorsByName, bare, snip);
                    AddSnip(_ctorsByType, typeText, snip);
                    break;
            }
        }

        private static void AddSnip(Dictionary<string, List<Ctor>> map, string key, Ctor snip)
        {
            if (!map.TryGetValue(key, out var list)) map[key] = list = new List<Ctor>();
            list.Add(snip);
        }

        public string TrackedType(string receiverText)
        {
            if (_trackedTypes.TryGetValue(receiverText, out var t)) return t;
            var bare = receiverText.StartsWith("this.", StringComparison.Ordinal)
                ? receiverText["this.".Length..]
                : receiverText;
            return _trackedTypes.TryGetValue(bare, out var t2) ? t2 : null;
        }

        public string ConstValue(string identifier) =>
            _consts.TryGetValue(identifier, out var v) ? v : null;

        /// Construction snippets bearing on this receiver, capped. By bound
        /// name first, then by the receiver's written or resolved type text
        /// -- so a construction-time `Timeout = ...` travels with call sites
        /// on the same client even when constructed elsewhere in the file.
        public List<Ctor> ConstructionsFor(string receiverText, string clientType)
        {
            if (_ctorsByName.TryGetValue(receiverText, out var byName))
            {
                return byName.Take(MaxCtorsEmitted).ToList();
            }
            // Resolved identities are namespace-qualified; written type text
            // usually is not. Match the bare type name against tracked ctors.
            var bareType = clientType.Contains('.') ? clientType[(clientType.LastIndexOf('.') + 1)..] : clientType;
            foreach (var key in new[] { clientType, bareType })
            {
                if (key.Length > 0 && _ctorsByType.TryGetValue(key, out var byType))
                {
                    return byType.Take(MaxCtorsEmitted).ToList();
                }
            }
            return new List<Ctor>();
        }
    }
}
