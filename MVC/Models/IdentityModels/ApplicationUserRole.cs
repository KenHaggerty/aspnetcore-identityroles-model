using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace MVC.Models
{
    public class ApplicationUserRole : IdentityUserRole<string>
    {
        public ApplicationRole Role { get; set; }

        public ApplicationUserRole() { }

    }
}