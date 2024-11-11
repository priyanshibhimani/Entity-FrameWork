using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;

namespace ProductManagemet.Controllers
{
    [Route("productRate")]
    public class ProductRateController : Controller
    {
        
        private IProductRateService _productRateService;

        public ProductRateController(IProductRateService productRateService)
        {
            _productRateService = productRateService;
        }

        #region Index
        public async Task<IActionResult> Index()
        {
            var productrates= await _productRateService.GetProductsAsync();

            return View(productrates); 
            
        }
        #endregion

    }
}
