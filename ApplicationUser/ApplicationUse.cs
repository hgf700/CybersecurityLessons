using Microsoft.AspNetCore.Identity;
using aspapp.Models.VM;

namespace aspapp.ApplicationUse
{
    public class ApplicationUser : IdentityUser
    {
        public bool MustChangePassword { get; set; } = true;

        public DateTime? LastPasswordChangeDate { get; set; }

        public DateTime? PasswordExpirationDate { get; set; }
        public DateTime? LastActivity { get; set; }

        public List<PasswordHistory> PasswordHistories { get; set; } = new();
    }
}
