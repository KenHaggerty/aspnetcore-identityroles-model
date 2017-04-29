using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AccountViewModels
{
    public class VerifyEmailViewModel
    {
        [Required]
        [Display(Name = "Login Name")]
        [ReadOnly(true)]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
