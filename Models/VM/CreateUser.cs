using System.ComponentModel.DataAnnotations;

namespace aspapp.Models.VM
{
    public class CreateUser
    {
        //public string UserName { get; set; }

        public string? Password { get; set; }

        public string? ConfirmPassword { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public bool MustChangePassword { get; set; } = true;

        public bool IsOneTimePassword { get; set; } = false;
    }

}
