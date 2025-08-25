using AuthorizationApplication.Api.Auth;
using AuthorizationApplication.Api.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// OpenAPI
builder.Services.AddOpenApi();

// Db + Identity
builder.Services.AddDbContext<ApplicationDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 6;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// JWT
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
var jwt = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()!;
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization(options =>
{
    // Require Admin role
    options.AddPolicy("RequireAdmin", policy =>
        policy.RequireRole("Admin"));

    // Require a claim "scope" with value "read:profile"
    options.AddPolicy("ReadProfileScope", policy =>
        policy.RequireClaim("scope", "read:profile"));

    // Require a claim "scope" with value "write:profile"
    options.AddPolicy("WriteProfileScope", policy =>
        policy.RequireClaim("scope", "write:profile"));

    // Combine requirements: must be Admin *and* have scope write:profile
    options.AddPolicy("AdminWriteProfile", policy =>
    {
        policy.RequireRole("Admin");
        policy.RequireClaim("scope", "write:profile");
    });
});

builder.Services.AddControllers();  // for controllers

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("client");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();               // maps AuthController & ProfileController
app.MapOpenApi("/openapi/{documentName}.json");

await IdentitySeeder.SeedRolesAndAdminAsync(app.Services);

app.Run();