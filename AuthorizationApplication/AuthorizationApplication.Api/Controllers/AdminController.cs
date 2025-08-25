using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationApplication.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        // Requires just Admin role
        [Authorize(Policy = "RequireAdmin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnly()
        {
            return Ok("✅ You are an Admin (role-based check passed).");
        }

        // Requires just manage:roles scope
        [Authorize(Policy = "ManageRolesScope")]
        [HttpGet("manage-roles-scope")]
        public IActionResult ManageRolesScope()
        {
            return Ok("✅ You have scope manage:roles (claim-based check passed).");
        }

        // Requires BOTH Admin role and manage:roles scope
        [Authorize(Policy = "AdminAndManageRoles")]
        [HttpGet("admin-and-scope")]
        public IActionResult AdminAndScope()
        {
            return Ok("✅ You are Admin AND have scope manage:roles.");
        }
    }
}
