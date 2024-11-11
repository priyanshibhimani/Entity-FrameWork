using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OfficeOpenXml;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using ProductManagemet.Services;
using System.Reflection.Metadata;
using System.Threading.Tasks;


namespace ProductManagemet.Controllers
{
    public class InvoiceController : Controller
    {
        private IInvoiceService _invoiceService;

        public InvoiceController(IInvoiceService invoiceService)
        {
            _invoiceService = invoiceService;
            ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
        }

        // GET: Invoices
        [HttpGet]
        [Route("invoice")]
 
        #region Index
           // GET: invoice/index
        public async Task<IActionResult> Index(int partyId)
        {
            var invoices=await _invoiceService.GetInvoiceAsync(partyId);
            var totalAmount = invoices.Sum(i => i.TotalAmount);
            ViewBag.TotalAmount = totalAmount;
            ViewBag.PartyId = partyId;
            return View(invoices);
        }
        #endregion

        #region Edit
        [HttpGet]
        public async Task<IActionResult> Edit(int id, int partyId)
        {
            var invoice=await _invoiceService.GetInvoiceByIdAsync(id);
            if (invoice == null)
            {
                return NotFound();
            }
            var products = await _invoiceService.GetProductAsync();
            ViewBag.Products = new SelectList(products, "ProductId", "ProductName");
            ViewBag.PartyId = partyId;
            //var assignedProducts = await _invoiceService.GetPartyWiseProductAsync(partyId);
            //ViewBag.Products = assignedProducts
            //    .Select(pwp => new { pwp.Product.ProductId, Text = $"{pwp.Product.ProductName} - {pwp.Product.ProductDescription}" })
            //    .ToList();

            //// Set the PartyId for the view (this will be used when creating the invoice or editing it)
            //ViewBag.PartyId = partyId;

            return View(invoice);
        }

        [HttpPost]
        public async Task<IActionResult> Edit(Invoice invoice)
        {
            var isDuplicateProduct = await _invoiceService.ProductEditExist(invoice.ProductId, invoice.InvoiceId,invoice.PartyId);

            if (isDuplicateProduct)
            {
                TempData["Error"] = "This product already exists in the list. Please update its quantity instead.";
                return RedirectToAction("Index", new { partyId = invoice.PartyId });
            }

            if (ModelState.IsValid)
            {
                var product = await _invoiceService.GetProductByIdAsync(invoice);
                if (product != null)
                {
                    invoice.TotalAmount = invoice.Quantity * product.ProductRate;
                    await _invoiceService.UpdateInvoiceAsync(invoice);
                    return RedirectToAction("Index", new { partyId = invoice.PartyId });
                }
                else
                {
                    ModelState.AddModelError("", "Product not found.");
                }
            }
            //var products = await _invoiceService.GetPartyWiseProductAsync(invoice.PartyId);
            //ViewBag.Products = products
            //    .Select(p => new { p.Product.ProductId, Text = $"{p.Product.ProductName} - {p.Product.ProductDescription}" })
            //    .ToList();

            //ViewBag.PartyId = invoice.PartyId;
            ViewBag.PartyId = invoice.PartyId;
            return View(invoice);
        }
        private async Task<bool> InvoiceExists(int id)
        {
            return await _invoiceService.SearchInvoiceAsync(id);
        }
        #endregion

        #region Generate Invoice
        [HttpPost]
        [Route("invoice/generatetotal/{partyId}")]

        public async Task<IActionResult> GenerateTotal(int partyId)
        {
            await _invoiceService.GenerateTotal(partyId);
            return RedirectToAction("Index", "PartyTotal");
        }
        #endregion

        #region Create
        [HttpGet]
        public async Task<IActionResult> Create(int partyId)
        {
            var assignedProducts = await _invoiceService.GetPartyWiseProductAsync(partyId);


            //// Prepare ViewBag.Products for the dropdown with ProductName - ProductDescription format
            //ViewBag.Products = assignedProducts
            //    .Select(pwp => new { pwp.Product.ProductId, Text = $"{pwp.Product.ProductName} - {pwp.Product.ProductDescription}" })
            //    .ToList();
            var invoice = new Invoice
            {
                PartyId = partyId,
                ProductId = null, 
                Quantity = 1 
            };

            ViewBag.Products = assignedProducts.Select(pwp => pwp.Product).ToList();
            

            return View(invoice);
        }

        // POST: invoice/create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Invoice invoice)
        {
            var existingProduct = await _invoiceService.ProductExist(invoice.ProductId,invoice.PartyId);

            if (existingProduct)
            {
                TempData["Error"] = "This product already exist in list update it's quantity.";
                return RedirectToAction("Index", new { partyId = invoice.PartyId });
            }
            if (ModelState.IsValid)
            {
                var product = await _invoiceService.GetProductByIdAsync(invoice);
                if (product != null)
                {
                    invoice.TotalAmount = invoice.Quantity * product.ProductRate; 
                }
                await _invoiceService.AddInvoiceAsync(invoice);

                return RedirectToAction("Index", new { partyId = invoice.PartyId });
            }
            ViewBag.Products = await _invoiceService.GetProductAsync();
            
            //var assignedProducts = await _invoiceService.GetPartyWiseProductAsync(invoice.PartyId);
            //ViewBag.Products = assignedProducts
            //    .Select(pwp => new { pwp.Product.ProductId, Text = $"{pwp.Product.ProductName} - {pwp.Product.ProductDescription}" })
            //    .ToList();
            return View(invoice);
        }
        #endregion

        #region Excel
        public async Task<IActionResult> DownloadExcel(int partyId)
        {
            var invoices=await _invoiceService.GetInvoiceAsync(partyId);
            using (var package = new ExcelPackage())
            {
                var worksheet = package.Workbook.Worksheets.Add("Invoices");
                worksheet.Cells[1, 1].Value = "Sr.No";
                worksheet.Cells[1, 2].Value = "Product Name";
                worksheet.Cells[1, 3].Value = "Product Rate";
                worksheet.Cells[1, 4].Value = "Quantity";
                worksheet.Cells[1, 5].Value = "Total Amount";


                int row = 2;
                int column = 1;
                foreach (var invoice in invoices)
                {
                    worksheet.Cells[row, 1].Value = column;
                    worksheet.Cells[row, 2].Value = invoice.Product?.ProductName;
                    worksheet.Cells[row, 3].Value = invoice.Product?.ProductRate;
                    worksheet.Cells[row, 4].Value = invoice.Quantity;
                    worksheet.Cells[row, 5].Value = invoice.TotalAmount;
                    row++;
                    column++;
                }

                var excelData = package.GetAsByteArray();
                return File(excelData, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Invoices.xlsx");
            }
        }
        #endregion

        #region Delete
        [HttpPost, ActionName("Delete")]
        public async Task<IActionResult> DeleteConfirmed(int id, int partyId)
        {
            await _invoiceService.DeleteInvoiceAsync(id);
            return RedirectToAction("Index", new { partyId });
        }
        #endregion

    }
}
