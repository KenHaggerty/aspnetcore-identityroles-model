using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace MVC.Models.MemberViewModels
{
    public class MemberIndexViewModel
    {
        [Required]
        [Key]
        public string UserName { get; set; }
        [Display(Name = "DisplayName")]
        public string DisplayName { get; set; }
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
        [Display(Name = "Roles")]
        public string RolesString { get; set; }
        [Display(Name = "External Logins")]
        public IList<UserLoginInfo> Logins { get; set; }

        public MemberIndexViewModel()
        {
        }

        public MemberIndexViewModel(ApplicationUser user, List<string> roles, IList<UserLoginInfo> exlogins) : base()
        {
            UserName = user.UserName;
            Email = user.Email;
            EmailConfirmed = user.EmailConfirmed;
            PhoneNumber = user.PhoneNumber;
            PhoneNumberConfirmed = user.PhoneNumberConfirmed;
            TwoFactorEnabled = user.TwoFactorEnabled;
            var rs = string.Empty;
            foreach (var r in roles)
            {
                rs += r + ',';
            }
            RolesString = rs.Length > 0 ? rs.Substring(0, rs.Length - 1) : "None";
            Logins = exlogins;
            //ExternalLoginsString = exlogins.Length > 0 ? exlogins.Substring(0, exlogins.Length - 1) : "None";
        }
    }
}
