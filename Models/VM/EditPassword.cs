using System.ComponentModel.DataAnnotations;

namespace aspapp.Models.VM
{
    public class EditPassword
    {
        [Required]
        [DataType(DataType.Password)]
        public string OldPassword;

        [Required]
        [DataType(DataType.Password)]
        public string NewPassword;

        [Required]
        [DataType(DataType.Password)]
        public string ConfirmPassword;
    }
}
