using System.ComponentModel.DataAnnotations;

namespace ProductManagemet.Models
{
    public class Product
    {
        [Key]
        public int ProductId { get; set; }

        public string ProductName { get; set; }

        public string ProductDescription { get; set; }

        public decimal ProductRate { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now; // Set default value to now

        public DateTime UpdatedAt { get; set; } = DateTime.Now; // Set default value to now
    }
}

