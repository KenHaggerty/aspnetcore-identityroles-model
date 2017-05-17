using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace MVC.Models.AdminViewModels
{
  public class UserViewModel
  {
    [Required]
    [Key]
    [RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Must be  letters or numbers. No spaces.")]
    [Display(Name = "Login Name")]
    public string UserName { get; set; }
    [Required]
    public string Email { get; set; }
    [Display(Name = "Email Verified")]
    public bool EmailConfirmed { get; set; }    
    [Display(Name = "2 Factor Enabled")]
    public bool TwoFactorEnabled { get; set; } = false;    
    [Display(Name = "Roles")]
    public string RolesString { get; set; }
    public bool CanDelete { get; set; } = true;

    public UserViewModel()
    {
      //MustChangePassword = true;       
    }

    public UserViewModel(ApplicationUser user, List<string> roles, string exlogins = "") : base()
    {
      UserName = user.UserName;
      Email = user.Email;
      EmailConfirmed = user.EmailConfirmed;
      TwoFactorEnabled = user.TwoFactorEnabled;
      roles = roles.OrderBy(q => q).ToList();
      var rstring = roles.Count > 0 ? string.Join(", ", roles) : "None";
      RolesString = rstring;
    }
  }

  public class CreateUserViewModel : UserViewModel
  {
    [Required]
    public string Password { get; set; }
    [Display(Name = "Must Change")]
    public bool MustChangePassword { get; set; } = true;
    [Display(Name = "Phone")]
    public string PhoneNumber { get; set; }
    [Display(Name = "External Logins")]
    public string ExternalLoginsString { get; set; }
    [Display(Name = "Send Email")]
    public bool SendEmail { get; set; } = true;

    public CreateUserViewModel()
    {
      //MustChangePassword = true;       
    }

  }

  public class EditUserViewModel : UserViewModel
  {
    public string Password { get; set; }
    [Display(Name = "Must Change")]
    public bool MustChangePassword { get; set; } = true;
    [Display(Name = "Phone")]
    public string PhoneNumber { get; set; }
    [Display(Name = "Send Email")]
    public bool SendEmail { get; set; }    
    [Display(Name = "External Logins")]
    public string ExternalLoginsString { get; set; }

    public EditUserViewModel()
    {
      //MustChangePassword = true;       
    }

    public EditUserViewModel(ApplicationUser user, string roles, string exlogins = "") : base()
    {
      UserName = user.UserName;
      Email = user.Email;
      EmailConfirmed = user.EmailConfirmed;
      PhoneNumber = user.PhoneNumber;
      TwoFactorEnabled = user.TwoFactorEnabled;
      MustChangePassword = user.MustChangePassword;
      RolesString = roles;
      ExternalLoginsString = exlogins.Length > 0 ? exlogins.Substring(0, exlogins.Length - 1) : "None";
    }
  }
}
