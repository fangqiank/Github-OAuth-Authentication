using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie")
    .AddOAuth("github", opts =>
    {
        opts.SignInScheme = "cookie";
        opts.ClientId = builder.Configuration["Github:ClientId"];
        opts.ClientSecret = builder.Configuration["Github:ClientSecret"];

        opts.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        opts.TokenEndpoint = "https://github.com/login/oauth/access_token";
        opts.CallbackPath = "/oauth/github-cb";
        opts.SaveTokens = true;
        opts.UserInformationEndpoint = "https://api.github.com/user";

        opts.ClaimActions.MapJsonKey("sub", "id");
        opts.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");

        opts.Events.OnCreatingTicket = async ctx =>
        {
            //ctx.HttpContext.RequestServices 
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            using var result = await ctx.Backchannel.SendAsync(request);
            var user = await result.Content.ReadFromJsonAsync<JsonElement>();
            ctx.RunClaimActions(user);
        };
    });

var app = builder.Build();

app.MapGet("/", (HttpContext ctx) =>
{
    ctx.GetTokenAsync("access_token");

    return ctx.User.Claims.Select(c => new
    {
        c.Type,
        c.Value
    }).ToList();
});

app.MapGet("/login", (HttpContext ctx) =>
{
    return Results.Challenge(
        new AuthenticationProperties
        {
            RedirectUri = "https://localhost:5001/"
        },

        authenticationSchemes: new List<string>
        {
            "github"
        }); 
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
//app.UseAuthorization();


app.Run();
