using ProductManagemet.Models;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace ProductManagemet.Models
{
    public class ProductRate
    {
        [Key]
        public int Id { get; set; }

        [ForeignKey("Product")]
        public int? ProductId { get; set; }
        public virtual Product? Product { get; set; }

        public decimal NewRate { get; set; }
        public DateTime UpdatedDate { get; set; } 
    }
}
