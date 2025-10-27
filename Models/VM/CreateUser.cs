namespace aspapp.Models.VM
{
    public class CreateUser
    {
        public string UserName { get; set; }    
        public string Password { get; set; }
        public string Email { get; set; }
        public bool MustChangePassword { get; set; } = true;
    }
}
