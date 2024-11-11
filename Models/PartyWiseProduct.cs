using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProductManagemet.Models
{
    public class PartyWiseProduct
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "PartyId is required.")]

        [ForeignKey("Party")]
        public int? PartyId { get; set; }

        [Required(ErrorMessage = "ProductId is required.")]

        [ForeignKey("Product")]
        public int? ProductId { get; set; }

        public virtual Party? Party { get; set; }
     
        public virtual Product? Product { get; set; }
    }
}

