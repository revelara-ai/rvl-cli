// G2 server-entry surfaces: minimal-API route registrations and middleware
// on a resolved WebApplication, plus MVC controller attributes.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;

namespace Fixture;

public static class Server
{
    public static void Start(string[] args)
    {
        var app = WebApplication.Create(args);
        app.MapGet("/health", () => "ok");
        app.MapPost("/users", (string body) => body);
        app.UseAuthentication();
        app.Run();
    }
}

public sealed class UsersController : ControllerBase
{
    [HttpGet("/users/{id}")]
    public string GetUser(string id) => id;

    [HttpPost("/users")]
    public string CreateUser(string body) => body;
}
