﻿using System.ComponentModel.DataAnnotations;

namespace MVC.Models.AccountViewModels
{
    public class LoginViewModel
    {
        [Required]
        [Display(Name = "Login Name")]
        public string UserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}