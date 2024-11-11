//using ProductManagemet.Context;
//using ProductManagemet.Models;
//using ProductManagemet.ServiceContracts;

//namespace ProductManagemet.Services
//{
//    public class PartyTotalService : IPartyTotalService
//    {
//        private readonly AppDbContext _context;

//        public PartyTotalService(AppDbContext context)
//        {
//            _context = context;
//        }

//        public  async Task<IEnumerable<PartyTotal>> GetProductTotalAsync(string sortOrder = null, string searchTerm = null)
//        {
//            var partyTotalsQuery = _context.PartyTotal
//           .Include(pt => pt.Party) // Include related Party data if necessary
//           .AsQueryable();

//            // Implement searching by party name if a search term is provided
//            if (!string.IsNullOrWhiteSpace(searchTerm))
//            {
//                partyTotalsQuery = partyTotalsQuery.Where(pt => pt.Party.PartyName.Contains(searchTerm));
//            }

//            // Implement sorting
//            switch (sortOrder)
//            {
//                case "name_desc":
//                    partyTotalsQuery = partyTotalsQuery.OrderByDescending(pt => pt.Party.PartyName);
//                    break;
//                case "name_asc":
//                    partyTotalsQuery = partyTotalsQuery.OrderBy(pt => pt.Party.PartyName);
//                    break;
//                default:
//                    break;
//            }

//            return  await partyTotalsQuery.ToListAsync();
//        }
//    }
//}
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ProductManagemet.Services
{
    public class PartyTotalService : IPartyTotalService
    {
        private readonly AppDbContext _context;

        public PartyTotalService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<PartyTotal>> GetProductTotalAsync(string sortOrder = null, string searchTerm = null)
        {
            var partyTotalsQuery = _context.PartyTotal
                .Include(pt => pt.Party) 
                .AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                partyTotalsQuery = partyTotalsQuery.Where(pt => pt.Party.PartyName.Contains(searchTerm));
            }

            switch (sortOrder)
            {
                case "name_desc":
                    partyTotalsQuery = partyTotalsQuery.OrderByDescending(pt => pt.Party.PartyName);
                    break;
                case "name_asc":
                    partyTotalsQuery = partyTotalsQuery.OrderBy(pt => pt.Party.PartyName);
                    break;
                default:
                    break;
            }

            return await partyTotalsQuery.ToListAsync();
        }
    }
}

