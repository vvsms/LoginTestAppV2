using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        // Add custom properties here
        public string FullName { get; set; } = string.Empty;
    }
}
