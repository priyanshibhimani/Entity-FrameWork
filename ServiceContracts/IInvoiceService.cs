using ProductManagemet.Models;
using System.Web.Mvc;

namespace ProductManagemet.ServiceContracts
{
    public interface IInvoiceService
    {
        Task<IEnumerable<Invoice>> GetInvoiceAsync(int partyId,string sortOrder = null, string searchTerm = null);
        Task<IEnumerable<PartyWiseProduct>> GetPartyWiseProductAsync(int partyId);
        Task<IEnumerable<Product>> GetProductAsync();
        Task UpdateInvoiceAsync(Invoice invoice);
        Task<Invoice> GetInvoiceByIdAsync(int id);
        Task<Product> GetProductByIdAsync(Invoice invoice);
        Task<bool> SearchInvoiceAsync(int id);
        Task AddInvoiceAsync(Invoice invoice);
        Task DeleteInvoiceAsync(int id);
        Task GenerateTotal(int partyId);
        Task<bool> ProductExist(int? id, int partyId);
        Task<bool> ProductEditExist(int? id,int invoiceId, int partyId);
        Task<IEnumerable<SelectListItem>> GetProductSelectListAsync();
    }
}
