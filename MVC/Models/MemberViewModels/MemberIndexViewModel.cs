using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

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

    public MemberIndexViewModel()
    {
    }

    public MemberIndexViewModel(ApplicationUser user, List<string> roles, IList<UserLoginInfo> exlogins)
    {
      UserName = user.UserName;
      Email = user.Email;
      EmailConfirmed = user.EmailConfirmed;
      PhoneNumber = user.PhoneNumber;
      PhoneNumberConfirmed = user.PhoneNumberConfirmed;
      TwoFactorEnabled = user.TwoFactorEnabled;
      roles = roles.OrderBy(q => q).ToList();
      var rstring = roles.Count > 0 ? string.Join(", ", roles) : "None";
      RolesString = rstring;
    }
  }
}
