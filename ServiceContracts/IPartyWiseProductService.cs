using ProductManagemet.Models;
using System.Web.Mvc;

namespace ProductManagemet.ServiceContracts
{
    public interface IPartyWiseProductService
    {
        Task<IEnumerable<PartyWiseProduct>> GetPartyWiseProductAsync();
        Task<IEnumerable<Party>> GetPartyAsync();
        Task<IEnumerable<Product>> GetProductAsync();
        Task<PartyWiseProduct> GetPartyWiseProductByIdAsync(int id);
        Task<Product> GetProductByIdAsync(int id);
        Task DeletePartyWiseProductAsync(int id);
        Task UpdatePartyWiseProductAsync(int id,PartyWiseProduct partyWiseProduct);  
        Task AddPartyWiseProductAsync(PartyWiseProduct partyWiseProduct);
        Task<bool> SearchPartyWiseptoductAsync(int id);   
        Task<bool> GetPartyWiseProductByName(PartyWiseProduct partyWiseProduct);
        Task<IEnumerable<SelectListItem>> GetProductSelectListAsync();
    }
}
