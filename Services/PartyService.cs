using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;

namespace ProductManagemet.Services
{
    public class PartyService: IPartyService
    {

        private readonly AppDbContext _context;

        public PartyService(AppDbContext context)
        {
            _context = context;
        }

        public async Task AddPartyAsync(Party party)
        {
            var p = new Party()
            {
                PartyName = party.PartyName,
                CreatedAt=party.CreatedAt,
                UpdatedAt=party.UpdatedAt
            };
            _context.Parties.Add(p);
            await _context.SaveChangesAsync();
        }

        public async Task DeletePartyAsync(int id)
        {
            var party = await _context.Parties.FindAsync(id);
            if (party != null)
            {
                _context.Parties.Remove(party);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<Party>> GetPartiesAsync(string sortOrder = null, string searchTerm = null)
        {
            var partiesQuery = _context.Parties.AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                partiesQuery = partiesQuery.Where(p => p.PartyName.Contains(searchTerm));
            }

            if (!string.IsNullOrWhiteSpace(sortOrder))
            {
                switch (sortOrder)
                {
                    case "name_desc":
                        partiesQuery = partiesQuery.OrderByDescending(p => p.PartyName);
                        break;
                    case "name_asc":
                        partiesQuery = partiesQuery.OrderBy(p => p.PartyName);
                        break;
                    default:
                        break;
                }

            }

            return await partiesQuery.ToListAsync();
        }

        public async Task<Party> GetPartiesByIdAsync(int id)
        {
            return await _context.Parties.FindAsync(id);
            
        }

        public async Task<bool> SearchPartyAsync(int id)
        {
            return  _context.Parties.Any(e => e.PartyId == id);
        }
        public async Task<bool> PartyExistsAsync(string partyName)
        {
            var existsParam = new SqlParameter
            {
                ParameterName = "@Exists",
                SqlDbType = System.Data.SqlDbType.Bit,
                Direction = System.Data.ParameterDirection.Output
            };

            var partyNameParam = new SqlParameter("@PartyName", partyName);
            await _context.Database.ExecuteSqlRawAsync(
                "EXEC CheckPartyExists @PartyName, @Exists OUTPUT",
                partyNameParam, existsParam);

            var existsValue = existsParam.Value;

            return existsValue != DBNull.Value && (bool)existsValue;
        }

        public async Task<bool> PartyExistsEditAsync(string partyName,int id)
        {
            return await _context.Parties.AnyAsync(p => p.PartyName == partyName&&p.PartyId!=id);
        }


        public async Task UpdatePartyAsync(Party party)
        {
            var p = new Party()
            {
                PartyId=party.PartyId,
                PartyName=party.PartyName,
                UpdatedAt=DateTime.Now,
            };
            _context.Parties.Update(p);
            await _context.SaveChangesAsync();
        }
       

    }
}
