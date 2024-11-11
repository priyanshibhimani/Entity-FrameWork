using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;

namespace ProductManagemet.Services
{
    public class ProductRateService : IProductRateService
    {
        private readonly AppDbContext _context;

        public ProductRateService(AppDbContext context)
        {
            _context = context;
        }
        #region Index
        public async Task<IEnumerable<ProductRate>> GetProductsAsync()
        {
            var productrates = await _context.ProductRates
           .Include(pwp => pwp.Product)
           .ToListAsync();
            return productrates;
        }
        #endregion
    }
}
