using System.Net.Http;
using System.Threading.Tasks;

public class Fetcher
{
    private readonly HttpClient _http = new HttpClient();

    public async Task<string> FetchAsync(string url)
    {
        return await _http.GetStringAsync(Normalize(url));
    }

    internal static string Normalize(string url)
    {
        return url.Trim();
    }

    public override string ToString() => Describe();
}
