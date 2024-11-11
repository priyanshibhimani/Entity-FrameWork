
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProductManagemet.Models
{
    public class PartyTotal
    {
        [Key]
    public int Id { get; set; }
        [ForeignKey("Party")]
        public int PartyId { get; set; }
        public virtual Party? Party { get; set; }
        public decimal TotalAmount { get; set; }
        public int TotalProducts { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
}

