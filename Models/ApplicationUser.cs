using Microsoft.AspNetCore.Identity;

namespace ProductsManagementSystem.Models
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string? PersonName { get; set; }

    }
}
