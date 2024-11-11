using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;

namespace ProductManagemet.Controllers
{
    public class PartyController : Controller
    {
        private IPartyService _partyService;

        public PartyController(IPartyService partyService)
        {
          
            _partyService = partyService;
        }
        #region Get
        [Route("Party")]
        [HttpGet]
        public async Task<IActionResult> Party(string sortOrder = null, string searchTerm = null)
        {
            var parties = await _partyService.GetPartiesAsync(sortOrder, searchTerm);

            ViewBag.CurrentSort = sortOrder;
            ViewBag.CurrentFilter = searchTerm;

            return View(parties);
        }
            public async Task<IActionResult> Details(int id)
        {
            var party = await _partyService.GetPartiesByIdAsync(id);
            if (party == null)
            {
                return NotFound(); 
            }
            return View(party);
        }
        #endregion

        #region Insert
        [HttpGet]
        [Route("Party/Create")]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [Route("Party/Create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Party party)
        {
            var existingParty = await _partyService.PartyExistsAsync(party.PartyName);

            if (existingParty)
            {
                TempData["Error"] = "Party with the same Name already exists.";
                return RedirectToAction("Index");
            }

            if (ModelState.IsValid)
            {
                party.CreatedAt = DateTime.Now;
                party.UpdatedAt = DateTime.Now;

                await _partyService.AddPartyAsync(party);
                return RedirectToAction("Index");
            }

            return View(party);
        }
        #endregion

        #region Edit
        [HttpGet]
        [Route("Party/Edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var party = await _partyService.GetPartiesByIdAsync(id);
            if (party == null)
            {
                return NotFound(); 
            }
            return View(party);
        }
   
        [HttpPost]
        [Route("Party/Edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Party party)
        {
            if (id != party.PartyId)
            {
                return BadRequest();            
            }
            var existingProduct = await _partyService.PartyExistsEditAsync(party.PartyName,party.PartyId);

            if (existingProduct == true)
            {
                TempData["Error"] = "Party with the same Name already exists.";
                return RedirectToAction("Index");
            }

            if (ModelState.IsValid)
            {
                try
                {
                    await _partyService.UpdatePartyAsync(party);
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (PartyExists(party.PartyId)==null)
                    {
                        return NotFound();
                    }
                    throw;                    
                }
                return RedirectToAction("Party"); 
            }
            return View(party); 
        }
        private async Task<bool> PartyExists(int id)
        {
            return await _partyService.SearchPartyAsync(id);
        }

        #endregion

        #region Delete
        public async Task<IActionResult> Delete(int id)
        {
            var party = await _partyService.GetPartiesByIdAsync(id);
            if (party == null)
            {
                return NotFound();
            }
            return View(party);

        }

   
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
           await _partyService.DeletePartyAsync(id);
            return RedirectToAction("Party"); 
        }
        #endregion
    }
}
