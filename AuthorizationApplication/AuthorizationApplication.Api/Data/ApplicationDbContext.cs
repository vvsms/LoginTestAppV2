using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthorizationApplication.Api.Data
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string UserId { get; set; } = default!;
        public string Token { get; set; } = default!;
        public DateTime ExpiresUtc { get; set; }
        public DateTime CreatedUtc { get; set; }
        public string? ReplacedByToken { get; set; }
        public DateTime? RevokedUtc { get; set; }

        public bool IsExpired => DateTime.UtcNow >= ExpiresUtc;
        public bool IsRevoked => RevokedUtc != null;
        public bool IsActive => !IsRevoked && !IsExpired;

        public ApplicationUser User { get; set; } = default!;
    }

    public class ApplicationUser : IdentityUser
    {
        // Add profile fields later if needed (e.g. FullName)
        // public string? FullName { get; set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<RefreshToken>(b =>
            {
                b.HasIndex(x => x.Token).IsUnique();
                b.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId);
            });
        }
    }
}