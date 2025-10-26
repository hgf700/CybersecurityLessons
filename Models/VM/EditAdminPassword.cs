using System.ComponentModel.DataAnnotations;

namespace aspapp.Models.VM
{
    public class EditAdminPassword
    {
        [Required]
        [DataType(DataType.Password)]
        public string OldPassword;

        [Required]
        [DataType(DataType.Password)]
        public string NewPassword;
    }
}
