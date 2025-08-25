using AuthorizationApplication.Api.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationApplication.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // all endpoints require a valid JWT
    public class ProfileController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ProfileController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        // GET: /api/profile/me
        [HttpGet("me")]
        public async Task<IActionResult> GetMe()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null)
                return Unauthorized();

            return Ok(new
            {
                user.Email,
                user.Id,
                Claims = User.Claims.Select(c => new { c.Type, c.Value })
            });
        }

        // Only users with scope = read:profile
        [Authorize(Policy = "ReadProfileScope")]
        [HttpGet("read-secure")]
        public IActionResult ReadSecure()
        {
            return Ok("You have the read:profile scope!");
        }

        // Only users with scope = write:profile
        [Authorize(Policy = "WriteProfileScope")]
        [HttpPost("write-secure")]
        public IActionResult WriteSecure()
        {
            return Ok("You have the write:profile scope!");
        }

        // Must be Admin AND have write:profile
        [Authorize(Policy = "AdminWriteProfile")]
        [HttpPost("admin-write")]
        public IActionResult AdminWriteSecure()
        {
            return Ok("You are an Admin with write:profile scope!");
        }
    }
}