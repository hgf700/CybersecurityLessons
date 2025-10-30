using Microsoft.AspNetCore.Identity;

namespace aspapp.ApplicationUser
{
    public class ApplicationUse : IdentityUser
    {
        public bool MustChangePassword { get; set; } = true;
    }
}
