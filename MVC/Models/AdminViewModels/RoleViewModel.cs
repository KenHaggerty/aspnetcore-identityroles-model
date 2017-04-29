using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AdminViewModels
{

    public class RoleViewModel
    {
        public bool Selected { get; set; }

        [Required]
        [Key]
        [RegularExpression("[a-zA-Z0-9-_]+", ErrorMessage = "Must be  letters, numbers, dashes and underscores. No spaces.")]
        public string Name { get; set; }
        public string Description { get; set; }

        public RoleViewModel()
        {
        }

        public RoleViewModel(ApplicationRole role)
        {
            Name = role.Name;
            Description = role.Description;
        }

    }
}
