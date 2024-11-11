using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using ProductManagemet.Services;

namespace ProductManagemet.Controllers
{
    [Route("partywiseproduct")]
    public class PartyWiseProductController : Controller
    {
        private IPartyWiseProductService _partyWiseProduct;

        public PartyWiseProductController( IPartyWiseProductService partyWiseProduct)
        {
            _partyWiseProduct = partyWiseProduct;
        }

        #region Index
        [HttpGet]
        public async Task<IActionResult> Index()
        {
           var partyWiseProducts=await _partyWiseProduct.GetPartyWiseProductAsync();

            return View(partyWiseProducts); 
        }
        #endregion

        #region Delete
        // GET: partywiseproduct/delete/5
        [HttpGet("delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var partyWiseProduct = await _partyWiseProduct.GetPartyWiseProductByIdAsync(id);

            if (partyWiseProduct == null)
            {
                return NotFound(); 
            }

            return View(partyWiseProduct); 
        }

        // POST: partywiseproduct/delete/5
        [HttpPost("delete/{id}")]
        [ValidateAntiForgeryToken]
    

        public async Task<IActionResult> DeleteConfirmed(int id)
        {
          await _partyWiseProduct.DeletePartyWiseProductAsync(id);

            return RedirectToAction(nameof(Index)); 
        }
        #endregion

        #region Edit
        // GET: PartyWiseProduct/Edit/5
        [HttpGet("edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            //var partyWiseProduct = await _partyWiseProduct.GetPartyWiseProductByIdAsync(id);

            //if (partyWiseProduct == null)
            //{
            //    return NotFound(); 
            //}

            //ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            //ViewBag.Products = await _partyWiseProduct.GetProductAsync();
            var partyWiseProduct = await _partyWiseProduct.GetPartyWiseProductByIdAsync(id);
            if (partyWiseProduct == null)
            {
                return NotFound();
            }
            ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            ViewBag.Products = await _partyWiseProduct.GetProductSelectListAsync();
            return View(partyWiseProduct);
            //return View(partyWiseProduct); 
        }

        // POST: PartyWiseProduct/Edit/5
        [HttpPost("edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,PartyId,ProductId,ProductRate")] PartyWiseProduct partyWiseProduct)
        {
            if (id != partyWiseProduct.Id)
            {
                return NotFound();
            }
            var existingProduct = await _partyWiseProduct.GetPartyWiseProductByName(partyWiseProduct);

            if (existingProduct == true)
            {
                TempData["Error"] = "Product with the same Party already exists.";
                return RedirectToAction("Index");
            }
            if (ModelState.IsValid)
            {
                try
                {
                    await _partyWiseProduct.UpdatePartyWiseProductAsync(id, partyWiseProduct);
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (PartyWiseProductExists(partyWiseProduct.Id) == null)
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            //ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            //ViewBag.Products = await _partyWiseProduct.GetProductAsync();
            ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            ViewBag.Products = await _partyWiseProduct.GetProductSelectListAsync();

            return View(partyWiseProduct);
        }

      
        private async Task<bool> PartyWiseProductExists(int id)
        {
            return await _partyWiseProduct.SearchPartyWiseptoductAsync(id);
        }
        #endregion

        #region create
        // GET: partywiseproduct/create
        [HttpGet("Create")]
        public async Task<IActionResult> Create()
        {

            //ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            //ViewBag.Products = await _partyWiseProduct.GetProductAsync();

            //return View();
           
                ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
                ViewBag.Products = await _partyWiseProduct.GetProductSelectListAsync();
                return View();
            
        }
        [HttpPost("Create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("PartyId,ProductId")] PartyWiseProduct partyWiseProduct)
        {
            var existingProduct = await _partyWiseProduct.GetPartyWiseProductByName(partyWiseProduct);

            if (existingProduct == true)
            {     
                TempData["Error"] = "Product with the same Party already exists.";
                return RedirectToAction("Index");
            }
            if (ModelState.IsValid)
            {
                await _partyWiseProduct.AddPartyWiseProductAsync(partyWiseProduct);
                return RedirectToAction(nameof(Index));
            }

            //ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
            //ViewBag.Products = await _partyWiseProduct.GetProductAsync();
         
                ViewBag.Parties = await _partyWiseProduct.GetPartyAsync();
                ViewBag.Products = await _partyWiseProduct.GetProductSelectListAsync();
               
            return View(partyWiseProduct);
        }
        #endregion
    }
}
