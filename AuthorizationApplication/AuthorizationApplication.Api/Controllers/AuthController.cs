using AuthorizationApplication.Api.Auth;
using AuthorizationApplication.Api.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationApplication.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _db;
        private readonly JwtSettings _jwtSettings;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext db,
            IOptions<JwtSettings> jwtOptions)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _jwtSettings = jwtOptions.Value;
        }

        // ========== REGISTER ==========
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
        {
            var user = new ApplicationUser { UserName = req.Email, Email = req.Email };
            var result = await _userManager.CreateAsync(user, req.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            // Optionally assign default role
            // await _userManager.AddToRoleAsync(user, "User");

            return Ok("User registered successfully");
        }

        // ========== LOGIN ==========
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest req)
        {
            var user = await _userManager.FindByEmailAsync(req.Email);
            if (user is null) return Unauthorized("Invalid credentials");

            if (!await _userManager.CheckPasswordAsync(user, req.Password))
                return Unauthorized("Invalid credentials");

            var tokens = await GenerateTokensAsync(user);

            return Ok(tokens);
        }

        // ========== REFRESH ==========
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] Dictionary<string, string>? body)
        {
            string? refreshToken = Request.Cookies["rtkn"];
            if (body != null && body.TryGetValue("refreshToken", out var bodyToken))
                refreshToken ??= bodyToken;

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Missing refresh token");

            var entry = await _db.RefreshTokens.Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == refreshToken);

            if (entry == null || !entry.IsActive)
                return Unauthorized("Invalid refresh token");

            // Rotate refresh token
            entry.RevokedUtc = DateTime.UtcNow;
            var newRefresh = CreateRefreshToken(entry.UserId, entry.Token);
            _db.RefreshTokens.Add(newRefresh);
            await _db.SaveChangesAsync();

            var tokens = await GenerateTokensAsync(entry.User, newRefresh);

            return Ok(tokens);
        }

        // ========== LOGOUT ==========
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refresh = Request.Cookies["rtkn"];
            if (!string.IsNullOrEmpty(refresh))
            {
                var entry = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refresh);
                if (entry != null && entry.IsActive)
                {
                    entry.RevokedUtc = DateTime.UtcNow;
                    await _db.SaveChangesAsync();
                }
            }
            Response.Cookies.Delete("rtkn", new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict });
            return Ok("Logged out successfully");
        }

        // ========== PRIVATE HELPERS ==========
        private async Task<object> GenerateTokensAsync(ApplicationUser user, RefreshToken? existingRefresh = null)
        {
            // Claims
            var roles = await _userManager.GetRolesAsync(user);
            var userClaims = await _userManager.GetClaimsAsync(user);

            var claims = new List<Claim>
{
    new(JwtRegisteredClaimNames.Sub, user.Id),
    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
    new(ClaimTypes.NameIdentifier, user.Id),
};

            // Add roles as claims
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            // Add extra claims from DB (includes scopes)
            claims.AddRange(userClaims);

            // Access token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenMinutes);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds);

            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Refresh token (new if not passed)
            var refresh = existingRefresh ?? CreateRefreshToken(user.Id);

            if (existingRefresh == null)
            {
                _db.RefreshTokens.Add(refresh);
                await _db.SaveChangesAsync();
            }

            // Set HttpOnly cookie for browsers
            if (_jwtSettings.IssueRefreshTokenCookie)
            {
                Response.Cookies.Append("rtkn", refresh.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = refresh.ExpiresUtc
                });
            }

            return _jwtSettings.ReturnRefreshTokenInBody
                ? new { AccessToken = accessToken, ExpiresUtc = expires, RefreshToken = refresh.Token }
                : new { AccessToken = accessToken, ExpiresUtc = expires };
        }

        private static RefreshToken CreateRefreshToken(string userId, string? replacedBy = null)
        {
            return new RefreshToken
            {
                UserId = userId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddDays(7), // configurable
                ReplacedByToken = replacedBy
            };
        }
    }
}