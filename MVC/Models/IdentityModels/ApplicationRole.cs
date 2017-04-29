using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace MVC.Models
{
    public class ApplicationRole : IdentityRole
    {
        public ApplicationRole() { }

        public ApplicationRole(string name, string description) : base(name)
        {
            Description = description;
        }
        public virtual string Description { get; set; }

        public override string ToString()
        {
            return Name + "  " + Id;
        }
    }
}
