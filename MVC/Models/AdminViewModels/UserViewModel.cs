using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AdminViewModels
{
    public class UserViewModel
    {
        [Required]
        [Key]
        [RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Must be  letters or numbers. No spaces.")]
        public string UserName { get; set; }

        [Required]
        public string Email { get; set; }
        [Display(Name = "Email Verified")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Phone")]
        public string PhoneNumber { get; set; }
        [Display(Name = "Phone Verified")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = "2 Factor Enabled")]
        public bool TwoFactorEnabled { get; set; } = false;

        [Required]
        public string Password { get; set; }


        [Display(Name = "Must Change")]
        public bool MustChangePassword { get; set; } = true;

        [Display(Name = "Welcome Email")]
        public bool SendWelcome { get; set; }

        [Display(Name = "Roles")]
        public string RolesString { get; set; }

        [Display(Name = "External Logins")]
        public string ExternalLoginsString { get; set; }

        public UserViewModel()
        {
            //MustChangePassword = true;       
        }

        public UserViewModel(ApplicationUser user, List<string> roles, string exlogins = "") : base()
        {
            UserName = user.UserName;
            Email = user.Email;
            EmailConfirmed = user.EmailConfirmed;
            PhoneNumber = user.PhoneNumber;
            PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            TwoFactorEnabled = user.TwoFactorEnabled;
            MustChangePassword = user.MustChangePassword;
            var rs = string.Empty;
            foreach (var r in roles)
            {
                rs += r + ',';
            }
            RolesString = rs.Length > 0 ? rs.Substring(0, rs.Length - 1) : "None";
            ExternalLoginsString = exlogins.Length > 0 ? exlogins.Substring(0, exlogins.Length - 1) : "None";
        }
    }
    public class EditUserViewModel
    {
        [Required]
        [Key]
        [RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Must be  letters or numbers. No spaces.")]
        public string UserName { get; set; }

        [Required]
        public string Email { get; set; }
        [Display(Name = "Email Verified")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Phone")]
        public string PhoneNumber { get; set; }
        [Display(Name = "Phone Verified")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = "2 Factor Enabled")]
        public bool TwoFactorEnabled { get; set; }

        public string Password { get; set; } 

        [Display(Name = "Must Change")]
        public bool MustChangePassword { get; set; } = true;

        [Display(Name = "Welcome Email")]
        public bool SendWelcome { get; set; }
        
        [Display(Name = "Roles")]
        public string RolesString { get; set; }

        [Display(Name = "External Logins")]
        public string ExternalLoginsString { get; set; }

        public EditUserViewModel()
        {
            //MustChangePassword = true;       
        }

        public EditUserViewModel(ApplicationUser user, List<string> roles, string exlogins = "") : base()
        {
            UserName = user.UserName;
            Email = user.Email;
            EmailConfirmed = user.EmailConfirmed;
            PhoneNumber = user.PhoneNumber;
            PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            TwoFactorEnabled = user.TwoFactorEnabled;
            MustChangePassword = user.MustChangePassword;
            var rs = string.Empty;
            foreach (var r in roles)
            {
                rs += r + ',';
            }
            RolesString = rs.Length > 0 ? rs.Substring(0, rs.Length - 1) : "None";
            ExternalLoginsString = exlogins.Length > 0 ? exlogins.Substring(0, exlogins.Length - 1) : "None";
        }
    }
}
