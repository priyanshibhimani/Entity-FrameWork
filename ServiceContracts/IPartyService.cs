using ProductManagemet.Context;
using ProductManagemet.Models;

namespace ProductManagemet.ServiceContracts
{
    public interface IPartyService
    {
        Task<IEnumerable<Party>> GetPartiesAsync(string sortOrder = null, string searchTerm = null);
        Task<Party> GetPartiesByIdAsync(int id);
        Task AddPartyAsync(Party party);
        Task UpdatePartyAsync(Party party);
        Task DeletePartyAsync(int id);
        Task<bool> SearchPartyAsync(int id);
        Task<bool> PartyExistsAsync(string partyName);
        Task<bool> PartyExistsEditAsync(string partyName,int id);


    }
}
