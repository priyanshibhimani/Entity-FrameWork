using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using System.Web.Mvc;

namespace ProductManagemet.Services
{
    public class InvoiceService : IInvoiceService
    {
        private readonly AppDbContext _context;

        public InvoiceService(AppDbContext context)
        {
            _context = context;
        }

        public async Task AddInvoiceAsync(Invoice invoice)
        {
             _context.Invoices.Add(invoice);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteInvoiceAsync(int id)
        {
            var invoice = await _context.Invoices.FindAsync(id);
            if (invoice != null)
            {
                _context.Invoices.Remove(invoice);
                await _context.SaveChangesAsync();
            }
        }

        public async Task GenerateTotal(int partyId)
        {
            var invoices = await _context.Invoices
                .Where(i => i.PartyId == partyId)
                .Include(i => i.Product)
                .ToListAsync();

            if (invoices.Any())
            {
                var totalAmount = invoices.Sum(i => i.TotalAmount);
                var totalProducts = invoices.Sum(i => i.Quantity); 

                foreach (var invoice in invoices)
                {
                    var invoiceEntry = new InvoiceEntry
                    {
                        PartyId = invoice.PartyId,
                        InvoiceDate = invoice.InvoiceDate,
                        Quantity = invoice.Quantity,
                        ProductId = invoice.ProductId,
                        TotalAmount = invoice.TotalAmount
                    };
                    _context.InvoiceEntry.Add(invoiceEntry);
                }

                _context.Invoices.RemoveRange(invoices);
                await _context.SaveChangesAsync();

                var partyTotal = new PartyTotal
                {
                    PartyId = partyId,
                    TotalAmount = totalAmount,
                    TotalProducts = totalProducts,

                };

                _context.PartyTotal.Add(partyTotal);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<Invoice>> GetInvoiceAsync(int partyId,string sortOrder = null, string searchTerm = null)
        {
            var invoices = await _context.Invoices
              .Where(i => i.PartyId == partyId)
              .Include(i => i.Product)
              .ToListAsync();
            return invoices;
        }

        public async Task<Invoice> GetInvoiceByIdAsync(int id)
        {
            return await _context.Invoices.FindAsync(id);
        }

        public async Task<IEnumerable<PartyWiseProduct>> GetPartyWiseProductAsync(int partyId)
        {
           return await _context.PartyWiseProducts
                .Where(pwp => pwp.PartyId == partyId)
                .Include(pwp => pwp.Product)
                .ToListAsync();

        }

        public async Task<IEnumerable<Product>> GetProductAsync()
        {
           return await _context.Products.ToListAsync();
        }

        public  async Task<Product> GetProductByIdAsync(Invoice invoice)
        {
            return await _context.Products.FindAsync(invoice.ProductId);
        }

        public async Task<bool> ProductEditExist(int? id, int invoiceId, int partyId)
        {
            return await _context.Invoices
            .Where(i => i.PartyId == partyId && i.ProductId == id && i.InvoiceId != invoiceId)
            .AnyAsync();
           
            //return await invoices.AnyAsync(i => i.ProductId == id && i.InvoiceId!=invoiceId);
        }

        public async Task<bool> ProductExist(int? id, int partyId)
        {
            return await _context.Invoices
        .Where(i => i.PartyId == partyId && i.ProductId == id )
        .AnyAsync();

           // return await _context.Invoices.AnyAsync(i=>i.ProductId== id);
        }

        public async Task<bool> SearchInvoiceAsync(int id)
        {
           return _context.Invoices.Any(e => e.InvoiceId == id);
        }

        public async Task UpdateInvoiceAsync(Invoice invoice)
        {
            _context.Update(invoice);
            await _context.SaveChangesAsync();
        }
        public async Task<IEnumerable<SelectListItem>> GetProductSelectListAsync()
        {
            return await _context.Products
                .Select(p => new SelectListItem
                {
                    Value = p.ProductId.ToString(),
                    Text = $"{p.ProductName} - {p.ProductDescription}"
                })
                .ToListAsync();
        }

    }
}
