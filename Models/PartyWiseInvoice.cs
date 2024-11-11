using System.ComponentModel.DataAnnotations.Schema;

namespace ProductManagemet.Models
{
    public class PartyWiseInvoice
    {
        public int Id { get; set; }
        [ForeignKey("Invoices")]
        public int InvoiceId { get; set; }
        public virtual Invoice? Invoices { get; set; }
        [ForeignKey("Parties")]
        public int PartyId { get; set; }
        public Party? Parties { get; set; }

    }
}
