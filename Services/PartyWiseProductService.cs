using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using System.Web.Mvc;
using static iText.StyledXmlParser.Jsoup.Select.Evaluator;

namespace ProductManagemet.Services
{
    public class PartyWiseProductService:IPartyWiseProductService
    {
        private readonly AppDbContext _context;

        public PartyWiseProductService(AppDbContext context)
        {
            _context = context;
        }

        #region Add
        public async Task AddPartyWiseProductAsync(PartyWiseProduct partyWiseProduct)
        {
         
            var product = await _context.Products.FindAsync(partyWiseProduct.ProductId);


            _context.Add(partyWiseProduct);
            await _context.SaveChangesAsync();

        }
        #endregion
        #region Delete
        public async Task DeletePartyWiseProductAsync(int id)
        {
            var partyWiseProduct = await _context.PartyWiseProducts.FindAsync(id);
            if (partyWiseProduct != null)
            {
                _context.PartyWiseProducts.Remove(partyWiseProduct);
                await _context.SaveChangesAsync();
            }
        }
        #endregion
        #region Get
        public async Task<IEnumerable<Party>> GetPartyAsync()
        {
            return await _context.Parties.ToListAsync();
        }

        public async Task<IEnumerable<PartyWiseProduct>> GetPartyWiseProductAsync()
        {
            var partyWiseProducts = await _context.PartyWiseProducts
             .Include(pwp => pwp.Product)  
             .Include(pwp => pwp.Party)     
             .ToListAsync();

            return partyWiseProducts;
        }
       
        public async Task<PartyWiseProduct> GetPartyWiseProductByIdAsync(int id)
        {
            var partyWiseProduct = await _context.PartyWiseProducts
               .Include(pwp => pwp.Product)
               .Include(pwp => pwp.Party)
               .FirstOrDefaultAsync(m => m.Id == id);
            return partyWiseProduct;
        }

        public  async Task<bool> GetPartyWiseProductByName(PartyWiseProduct partyWiseProduct)
        {
           bool k= await _context.PartyWiseProducts.AnyAsync(p => p.PartyId == partyWiseProduct.PartyId && p.ProductId == partyWiseProduct.ProductId);
            return k;
        }

        public async Task<IEnumerable<Product>> GetProductAsync()
        {
            return await _context.Products.ToListAsync();
        }

        public async Task<Product> GetProductByIdAsync(int id)
        {
             return await _context.Products.FindAsync(id);
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

        #endregion
        #region update
        public async Task<bool> SearchPartyWiseptoductAsync(int id)
        {
           return  _context.PartyWiseProducts.Any(e => e.Id == id);
        }

        public async Task UpdatePartyWiseProductAsync(int id,PartyWiseProduct partyWiseProduct)
        {
            var product = await _context.Products.FindAsync(partyWiseProduct.ProductId);

            _context.Update(partyWiseProduct);
            await _context.SaveChangesAsync();
        }
        #endregion
    }
}
