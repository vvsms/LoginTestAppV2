using System.Security.Claims;
using Auth.Domain.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly ITokenService _tokenService;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext db,
            ITokenService tokenService,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _db = db;
            _tokenService = tokenService;
            _signInManager = signInManager;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var user = new ApplicationUser { UserName = dto.Email, Email = dto.Email, FullName = dto.FullName, EmailConfirmed = true };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors.Select(e => e.Description));

            // assign role 'User' by default
            await _userManager.AddToRoleAsync(user, "User");

            return Ok(new { message = "Registered" });
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return Unauthorized("Invalid credentials");

            // check for lockout
            if (await _userManager.IsLockedOutAsync(user))
                return Unauthorized("Account is locked");

            // verify password
            if (!await _userManager.CheckPasswordAsync(user, dto.Password))
            {
                await _userManager.AccessFailedAsync(user);
                return Unauthorized("Invalid credentials");
            }

            // reset failed access count
            await _userManager.ResetAccessFailedCountAsync(user);

            // If 2FA is enabled, require second step
            if (user.TwoFactorEnabled)
            {
                // We can return a 2fa required response and a temporary flag (for simplicity return code)
                return Unauthorized(new { twoFactorRequired = true, message = "Two-factor code required" });
            }

            var roles = await _userManager.GetRolesAsync(user);

            var (accessToken, accessExpires) = _tokenService.GenerateAccessToken(user, roles);
            var (refreshToken, refreshTokenEntity) = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

            // persist refresh token
            refreshTokenEntity.UserId = user.Id;
            _db.RefreshTokens.Add(refreshTokenEntity);
            await _db.SaveChangesAsync();

            // audit log entry (simplified)
            _db.AuditEntries.Add(new AuditEntry { Action = "Login", UserId = user.Id, Timestamp = DateTime.UtcNow, Details = "User logged in", IpAddress = refreshTokenEntity.CreatedByIp });
            await _db.SaveChangesAsync();

            return Ok(new
            {
                accessToken,
                accessTokenExpires = accessExpires,
                refreshToken // send raw refresh token to client (store hashed server-side)
            });
        }

        // POST: api/auth/refresh
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRefreshRequest req)
        {
            // client sends refresh token string
            var providedHash = _tokenService.ComputeSha256Hash(req.RefreshToken);

            var refreshTokenEntity = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == providedHash);
            if (refreshTokenEntity == null)
                return Unauthorized("Invalid refresh token");

            if (refreshTokenEntity.Revoked || refreshTokenEntity.Expires <= DateTime.UtcNow)
                return Unauthorized("Refresh token expired or revoked");

            // rotate: revoke old and issue new
            refreshTokenEntity.Revoked = true;
            refreshTokenEntity.RevokedAt = DateTime.UtcNow;
            refreshTokenEntity.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            var user = await _userManager.FindByIdAsync(refreshTokenEntity.UserId);
            if (user == null) return Unauthorized("Invalid refresh token user");

            var (newRefreshToken, newRefreshEntity) = _tokenService.GenerateRefreshToken(HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            newRefreshEntity.UserId = user.Id;
            newRefreshEntity.ReplacedByToken = null;

            // link replacement
            refreshTokenEntity.ReplacedByToken = newRefreshEntity.TokenHash; // store replaced token hash for audit
            _db.RefreshTokens.Add(newRefreshEntity);

            // generate new access token
            var roles = await _userManager.GetRolesAsync(user);
            var (newAccessToken, expires) = _tokenService.GenerateAccessToken(user, roles);

            await _db.SaveChangesAsync();

            // audit
            _db.AuditEntries.Add(new AuditEntry { Action = "TokenRefresh", UserId = user.Id, Timestamp = DateTime.UtcNow, Details = "Rotated refresh token", IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown" });
            await _db.SaveChangesAsync();

            return Ok(new { accessToken = newAccessToken, accessTokenExpires = expires, refreshToken = newRefreshToken });
        }

        // POST: api/auth/revoke
        [Authorize]
        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke([FromBody] TokenRevokeRequest req)
        {
            var providedHash = _tokenService.ComputeSha256Hash(req.RefreshToken);
            var rt = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == providedHash);

            if (rt == null) return NotFound("Token not found");

            rt.Revoked = true;
            rt.RevokedAt = DateTime.UtcNow;
            rt.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            await _db.SaveChangesAsync();

            return Ok(new { message = "Revoked" });
        }

        // --- Example 2FA (TOTP) endpoints
        // GET: api/auth/enable-authenticator
        [Authorize]
        [HttpGet("enable-authenticator")]
        public async Task<IActionResult> GetAuthenticatorSetup()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            // ensure user has an authenticator key
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            // create a shared key uri (otpauth uri) for authenticator apps
            var email = user.Email;
            var otpUri = $"otpauth://totp/AuthApp:{email}?secret={key}&issuer=AuthApi";

            return Ok(new { otpUri });
        }

        // POST: api/auth/verify-2fa
        [Authorize]
        [HttpPost("verify-2fa")]
        public async Task<IActionResult> Verify2fa([FromBody] TwoFactorDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            var valid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, dto.Code);
            if (!valid) return BadRequest("Invalid 2FA code");

            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            return Ok(new { message = "2FA enabled" });
        }
    }

    // DTOs
    public record RegisterDto(string Email, string Password, string? FullName);
    public record LoginDto(string Email, string Password);
    public record TokenRefreshRequest(string RefreshToken);
    public record TokenRevokeRequest(string RefreshToken);
    public record TwoFactorDto(string Code);
}
