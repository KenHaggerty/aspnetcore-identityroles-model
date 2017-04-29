using System.ComponentModel.DataAnnotations;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace MVC.Models.AccountViewModels
{
    public class MustChangePasswordViewModel
    {
        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public string OldPassword { get; set; }
        public string ReturnURL { get; set; }

        public MustChangePasswordViewModel()
        {
        }

        public MustChangePasswordViewModel(string id, string returnUrl)
        {
            OldPassword = id;
            ReturnURL = returnUrl;
        }
    }

}