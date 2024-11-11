using ProductManagemet.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProductManagemet.Models
{
    public class Invoice
    {
        public int InvoiceId { get; set; }

        [ForeignKey("Parties")]
        public int PartyId { get; set; }
        public Party? Parties { get; set; }

        public DateTime InvoiceDate { get; set; } = DateTime.Now; 
        public int Quantity { get; set; }

        [ForeignKey("Product")]
        public int? ProductId { get; set; }
        public virtual Product? Product { get; set; }

        public decimal TotalAmount { get; set; }  

        public void CalculateTotalAmount(decimal productPrice)
        {
            TotalAmount = Quantity * productPrice;
        }
    }
}
