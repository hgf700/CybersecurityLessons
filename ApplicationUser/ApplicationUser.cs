using Microsoft.AspNetCore.Identity;

namespace aspapp.ApplicationUser
{
    public class ApplicationUser : IdentityUser
    {
        public bool MustChangePassword { get; set; } = true;
    }
}
