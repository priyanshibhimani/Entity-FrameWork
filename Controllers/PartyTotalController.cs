using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using System.Threading.Tasks;

namespace ProductManagement.Controllers
{
    public class PartyTotalController : Controller
    {
        private readonly IPartyTotalService _partyTotalService;

        public PartyTotalController(IPartyTotalService partyTotalService)
        {
            _partyTotalService = partyTotalService;
        }
        #region Index
       
        [HttpGet]
        [Route("partytotal/Index")]
        public async Task<IActionResult> Index(string sortOrder = null, string searchTerm = null)
        {
       


            var partyTotals = await _partyTotalService.GetProductTotalAsync(sortOrder,searchTerm);

            ViewBag.CurrentSort = sortOrder; 
            ViewBag.CurrentSearch = searchTerm; 

            return View(partyTotals);
        }


        #endregion

    }
}



