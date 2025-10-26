namespace aspapp.Models
{
    public class SecuritySettings
    {
        public int Id { get; set; }
        public int RequiredLength { get; set; }
        public bool RequireDigit { get; set; }
        public bool RequireUppercase { get; set; }
        public bool RequireNonAlphanumeric { get; set; }
    }

}
