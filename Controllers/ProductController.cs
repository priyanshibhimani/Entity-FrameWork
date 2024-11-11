using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using ProductManagemet.Services;

namespace ProductManagemet.Controllers
{
    public class ProductController : Controller
    {
        private IProductService _productService;
      
        public ProductController(IProductService productService)
        {

            _productService = productService;   
        }
        #region Index
        public async Task<IActionResult> Index(string sortOrder = null, string searchTerm = null)
        {
             var products= await _productService.GetProductAsync(sortOrder, searchTerm);

            ViewBag.CurrentSort = sortOrder;
            ViewBag.CurrentSearch = searchTerm; 

            return View(products);
        }
        #endregion
        #region Details

        [Route("Product/{id}")]
        public async Task<IActionResult> Details(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                return NotFound();
            }
            return View(product);
        }
        #endregion
        #region Create
        [HttpGet]
        [Route("Product/Create")]
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        [Route("Product/Create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Product product)
        { 
            var existingProduct = await _productService.ProductExistsAsync(product.ProductName,product.ProductDescription);

            if (existingProduct == true)
            {
                TempData["Error"] = "Product with the same Name and Description already exists.";
                return RedirectToAction("Index");
            }
            if (ModelState.IsValid)
            {
                product.CreatedAt = DateTime.Now;
                product.UpdatedAt = DateTime.Now;
                await _productService.AddProductAsync(product);
                return RedirectToAction("Index");
            }
        
            return View(product);
        }
        #endregion
        #region Edit
        [HttpGet]
        [Route("Product/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                return NotFound();
            }
            return View(product);
        }

        [HttpPost]
        [Route("Product/Edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Product product)
        {
            if (id != product.ProductId)
            {
                return BadRequest();
            }
            var existingProduct = await _productService.ProductExistsEditAsync(product.ProductName, product.ProductDescription, product.ProductId);

            if (existingProduct == true)
            {
                TempData["Error"] = "Product with the same Name already exists.";
                return RedirectToAction("Index");
            }
            if (ModelState.IsValid)
            {
                await _productService.UpdateProductAsync(id, product);
                return RedirectToAction("Index");
            }
            return View(product);
        }





        private async Task<bool> PartyExists(int id)
        {
            return await _productService.SearchProductAsync(id);
        }

        #endregion
        #region Delete
        public async Task<IActionResult> Delete(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                return NotFound();
            }
            return View(product);
        }


        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
           await _productService.DeleteProductAsync(id);
            return RedirectToAction("Index");
        }
        #endregion
    }
}
