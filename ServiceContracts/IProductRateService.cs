using ProductManagemet.Models;

namespace ProductManagemet.ServiceContracts
{
    public interface IProductRateService
    {
        Task<IEnumerable<ProductRate>> GetProductsAsync();
    }
}
