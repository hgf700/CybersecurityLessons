using Microsoft.Extensions.Options;

namespace aspapp.Models
{
    public class PasswordPolicy
    {
        public int Id { get; set; }
        public int RequiredLength { get; set; }
        public bool RequireDigit { get; set; }
        public bool RequireUppercase { get; set; }
        public bool RequireNonAlphanumeric { get; set; }
    }
}