// The unsized-construction lane: an object that takes a bound, built with no
// bound. Each method holds ONE construction, so a packet is found by the name
// of its enclosing method. The bounded form of each identity sits next to it
// and gives no packet.
//
// `using System.IO` is written out: csindex does not load the project file,
// so it does not see the SDK's implicit usings, and `File` would not resolve.

using System.IO;
using System.Threading.Channels;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Fixture;

public sealed class Bounds
{
    private const long MaxEntries = 1024;
    private static readonly TimeSpan ScanEvery = TimeSpan.FromMinutes(1);

    // -- queue ---------------------------------------------------------------

    public Channel<string> UnboundedChannel()
    {
        return Channel.CreateUnbounded<string>();
    }

    public Channel<string> BoundedChannel()
    {
        return Channel.CreateBounded<string>(100);
    }

    // -- read ----------------------------------------------------------------

    public string WholeText(string path)
    {
        return File.ReadAllText(path);
    }

    public byte[] WholeBytes(string path)
    {
        return File.ReadAllBytes(path);
    }

    public int StreamedRead(string path)
    {
        using var stream = File.OpenRead(path);
        var buffer = new byte[4096];
        return stream.ReadAtLeast(buffer, 1, throwOnEndOfStream: false);
    }

    // -- cache ---------------------------------------------------------------

    public IMemoryCache UnsizedCache()
    {
        return new MemoryCache(new MemoryCacheOptions());
    }

    public IMemoryCache SizedCache()
    {
        return new MemoryCache(new MemoryCacheOptions { SizeLimit = 1024 });
    }

    /// SizeLimit = null is the library's "no limit": still a packet, and the
    /// value rides it.
    public IMemoryCache NullLimitCache()
    {
        return new MemoryCache(new MemoryCacheOptions { SizeLimit = null });
    }

    /// The limit is set on the options object after it is built.
    public IMemoryCache LaterSizedCache()
    {
        var options = new MemoryCacheOptions();
        options.SizeLimit = MaxEntries;
        return new MemoryCache(options);
    }

    /// Options.Create is a wrapper, not a bound. The scan frequency is an
    /// option, and it is not a constant.
    public IMemoryCache WrappedCache()
    {
        return new MemoryCache(Options.Create(new MemoryCacheOptions { ExpirationScanFrequency = ScanEvery }));
    }

    /// The options come from somewhere this method cannot see.
    public IMemoryCache InjectedOptionsCache(IOptions<MemoryCacheOptions> options)
    {
        return new MemoryCache(options);
    }

    public void RegisterUnsized(IServiceCollection services)
    {
        services.AddMemoryCache();
    }

    public void RegisterSized(IServiceCollection services)
    {
        services.AddMemoryCache(options => options.SizeLimit = MaxEntries);
    }

    public void RegisterUntracked(IServiceCollection services)
    {
        services.AddMemoryCache(options => { options.TrackStatistics = true; });
    }
}
