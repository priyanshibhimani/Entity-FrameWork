using ProductManagemet.Models;

namespace ProductManagemet.ServiceContracts
{
    public interface IPartyTotalService
    {
        Task<IEnumerable<PartyTotal>> GetProductTotalAsync(string sortOrder = null, string searchTerm = null);
    }
}
