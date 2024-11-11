using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Context;
using ProductManagemet.Models;
using ProductManagemet.ServiceContracts;
using static iText.StyledXmlParser.Jsoup.Select.Evaluator;

namespace ProductManagemet.Services
{
    public class ProductService : IProductService
    {
        private readonly AppDbContext _context;

        public ProductService(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IEnumerable<Product>> GetProductAsync(string sortOrder = null, string searchTerm = null)
        {
            var productsQuery = _context.Products.AsQueryable();

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                productsQuery = productsQuery.Where(p => p.ProductName.Contains(searchTerm));
                //productsQuery = productsQuery.Where(p => p.ProductDescription.Contains(searchTerm));
            }

            switch (sortOrder)
            {
                case "name_desc":
                    productsQuery = productsQuery.OrderByDescending(p => p.ProductName);
                    break;
                case "name_asc":
                    productsQuery = productsQuery.OrderBy(p => p.ProductName);
                    break;
                default:
                    break;
            }

            return await productsQuery.ToListAsync();

        }

        public async Task AddProductAsync(Product product)
        {
            _context.Products.Add(product);
            await _context.SaveChangesAsync();
        }


        public async Task DeleteProductAsync(int id)
        {
            var product = await _context.Products.FindAsync(id);
            if (product != null)
            {
                _context.Products.Remove(product);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<Product> GetProductByIdAsync(int id)
        {
            return await _context.Products.FindAsync(id);
        }

        public async Task UpdateProductAsync(int id, Product product)
        {
            
            var existingProduct = await _context.Products.FindAsync(id);
            
            var productRate = new ProductRate
            {
                ProductId = existingProduct.ProductId,
                NewRate = existingProduct.ProductRate,
                UpdatedDate = DateTime.Now,
                
            };
            if (product.ProductRate != existingProduct.ProductRate)
            {
                _context.ProductRates.Add(productRate);
                await _context.SaveChangesAsync();
            }
            existingProduct.ProductName = product.ProductName;
            existingProduct.ProductDescription = product.ProductDescription;
            existingProduct.ProductRate = product.ProductRate;
            existingProduct.UpdatedAt = DateTime.Now;
            await _context.SaveChangesAsync();

        }

        public async Task<bool> SearchProductAsync(int id)
        {
            return _context.Products.Any(e => e.ProductId == id);
        }

        //public async Task<bool> ProductExistsAsync(string productName, string productDescription)
        //{
        //    var exists = await _context.Products
        //        .AnyAsync(p => p.ProductName.ToLower() == productName.ToLower()
        //                    && p.ProductDescription.ToLower() == productDescription.ToLower());
        //    return exists;
        //}
        public async Task<bool> ProductExistsAsync(string productName, string productDescription)
        {
            // Define the output parameter
            var existsParam = new SqlParameter
            {
                ParameterName = "@Exists",
                SqlDbType = System.Data.SqlDbType.Bit,
                Direction = System.Data.ParameterDirection.Output
            };

            // Define the input parameters
            var productNameParam = new SqlParameter("@ProductName", productName);
            var productDescriptionParam = new SqlParameter("@ProductDescription", productDescription);

            // Execute the stored procedure
            await _context.Database.ExecuteSqlRawAsync(
                "EXEC CheckProductExists @ProductName, @ProductDescription, @Exists OUTPUT",
                productNameParam, productDescriptionParam, existsParam);

            // Retrieve the output parameter value
            var existsValue = existsParam.Value;

            // Debugging line to print the value of Exists parameter
            Console.WriteLine($"Exists value: {existsValue}");

            // Check if the value is not DBNull and cast to bool
            return existsValue != DBNull.Value && (bool)existsValue;
        }



        public async Task<bool> ProductExistsEditAsync(string productName, string productDescription, int id)
        {

            productDescription = productDescription.ToLower();
            var exists = await _context.Products
      .AnyAsync(p => p.ProductName == productName
                  && p.ProductDescription == productDescription
                  && p.ProductId != id);

           

            return exists;
        }


    }
}
