using AuthorizationApplication.Api.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationApplication.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")] // Only admins can manage roles
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public RoleController(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        // ========= Create a new role =========
        [HttpPost("create")]
        public async Task<IActionResult> CreateRole([FromQuery] string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return BadRequest("Role name cannot be empty.");

            if (await _roleManager.RoleExistsAsync(roleName))
                return BadRequest("Role already exists.");

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
            return result.Succeeded ? Ok($"Role '{roleName}' created.") : BadRequest(result.Errors);
        }

        // ========= List all roles =========
        [HttpGet("list")]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles.Select(r => r.Name).ToList();
            return Ok(roles);
        }

        // ========= Assign a role to a user =========
        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromQuery] string userId, [FromQuery] string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found.");

            if (!await _roleManager.RoleExistsAsync(roleName))
                return NotFound("Role not found.");

            var result = await _userManager.AddToRoleAsync(user, roleName);
            return result.Succeeded ? Ok($"Role '{roleName}' assigned to {user.Email}.") : BadRequest(result.Errors);
        }

        // ========= Remove a role from a user =========
        [HttpPost("remove")]
        public async Task<IActionResult> RemoveRole([FromQuery] string userId, [FromQuery] string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found.");

            if (!await _roleManager.RoleExistsAsync(roleName))
                return NotFound("Role not found.");

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            return result.Succeeded ? Ok($"Role '{roleName}' removed from {user.Email}.") : BadRequest(result.Errors);
        }

        // ========= Get roles of a specific user =========
        [HttpGet("user-roles")]
        public async Task<IActionResult> GetUserRoles([FromQuery] string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found.");

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }
    }
}
