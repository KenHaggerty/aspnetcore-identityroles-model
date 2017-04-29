using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace MVC.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public virtual bool MustChangePassword { get; set; }

        public ApplicationUser()
        {
            MustChangePassword = false;
        }
        public ApplicationUser(bool mustchangepassword)
        {
            MustChangePassword = mustchangepassword;
        }
    }
}
