using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthorizationApplication.Api.Data
{
    public static class IdentitySeeder
    {
        public static async Task SeedRolesAndAdminAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            string[] roles = new[] { "Admin", "User" };

            // Ensure roles exist
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // Ensure an admin user exists
            var adminEmail = "admin@authapp.com";
            var adminPassword = "Admin123!"; // ⚠️ change this in production

            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };
                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    await userManager.AddClaimAsync(adminUser, new Claim("scope", "manage:roles"));
                }
            }
            else
            {
                // Ensure user has Admin role
                if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    await userManager.AddClaimAsync(adminUser, new Claim("scope", "manage:roles"));
                }
            }
        }
    }
}