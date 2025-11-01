using aspapp.ApplicationUser;

namespace aspapp.Models.VM
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public ApplicationUse User { get; set; }

        public string PasswordHash { get; set; }

        public DateTime ChangedAt { get; set; } = DateTime.UtcNow;
    }
}
