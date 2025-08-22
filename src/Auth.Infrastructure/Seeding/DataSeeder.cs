using Auth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Infrastructure.Seeding
{
    public static class DataSeeder
    {
        public static async Task SeedRolesAndSuperAdminAsync(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            // Roles to ensure
            var roles = new[] { "Admin", "Manager", "User" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // Super admin details from config (for safety, use secrets or env vars in prod)
            var adminEmail = config["SuperAdmin:Email"] ?? "superadmin@example.com";
            var adminPassword = config["SuperAdmin:Password"] ?? "ChangeThisP@ssw0rd!";

            var existing = await userManager.FindByEmailAsync(adminEmail);
            if (existing == null)
            {
                var adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    FullName = "Super Admin"
                };

                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRolesAsync(adminUser, roles);
                }
                else
                {
                    // log failures - in production, surface to admin
                    throw new Exception($"Failed to create superadmin: {string.Join(';', result.Errors.Select(e => e.Description))}");
                }
            }
        }
    }
}