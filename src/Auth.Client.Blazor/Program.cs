using Auth.Client.Blazor;
using Auth.Client.Blazor.Services;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// Register BlazoredLocalStorage
builder.Services.AddBlazoredLocalStorage();
// register our auth service
builder.Services.AddScoped<ApiAuthService>();

await builder.Build().RunAsync();
