using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Domain.Entities
{
    public class AuditEntry
    {
        public int Id { get; set; }
        public string Action { get; set; } = default!; // e.g. "Login", "RoleChange"
        public string? UserId { get; set; }
        public string Details { get; set; } = default!;
        public DateTime Timestamp { get; set; }
        public string IpAddress { get; set; } = default!;
    }
}
