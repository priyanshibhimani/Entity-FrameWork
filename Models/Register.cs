using Microsoft.AspNetCore.Mvc;
using ProductsManagementSystem.Enums;
using System.ComponentModel.DataAnnotations;

namespace ProductManagemet.Models
{
    public class Register
    {
        [Required(ErrorMessage = "Add person Name, it can't be blank")]
        public string PersonName { get; set; }


        [Required(ErrorMessage = "Add Email, it can't be blank")]
        [EmailAddress(ErrorMessage = "Add proper email address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password can't be blank")]
        [DataType(DataType.Password)]
        public string Password { get; set; }


        [Required(ErrorMessage = "Confirm Password can't be blank")]
        [Compare("Password", ErrorMessage = "Password and confirm Password does not Match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }

        public UserRoleOptions UserType { get; set; } = UserRoleOptions.User;
    }
}
