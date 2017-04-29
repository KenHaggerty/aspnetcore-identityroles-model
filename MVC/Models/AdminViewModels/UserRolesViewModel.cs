using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AdminViewModels
{
    public class UserRolesViewModel
    {
        [Key]
        public string UserName { get; set; }
        public List<RoleViewModel> Roles { get; set; }
        public UserRolesViewModel(ApplicationUser user) :base()
        {
            UserName = user.UserName;
            //Roles = user.Roles;
        }
    }
}
