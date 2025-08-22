using Auth.Domain.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<AuditEntry> AuditEntries { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // configure relationships & indexes
            builder.Entity<RefreshToken>()
                .HasIndex(r => r.TokenHash)
                .IsUnique(false);

            builder.Entity<RefreshToken>()
                .Property(r => r.TokenHash)
                .IsRequired();

            builder.Entity<AuditEntry>()
                .Property(a => a.Timestamp)
                .HasDefaultValueSql("GETUTCDATE()");
        }
    }
}