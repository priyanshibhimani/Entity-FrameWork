using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using ProductManagemet.Models;
using ProductsManagementSystem.Models;
namespace ProductManagemet.Context
{
    public class AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<Product> Products { get; set; }
        public DbSet<Party> Parties { get; set; }

        public DbSet<PartyWiseProduct> PartyWiseProducts { get; set; } // Add this line
        public DbSet<ProductRate> ProductRates { get; set; }    
        public DbSet<Invoice> Invoices { get; set; }
        public DbSet<PartyTotal> PartyTotal { get; set; }
        public DbSet<InvoiceEntry> InvoiceEntry { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<IdentityUserLogin<Guid>>().HasKey(iul => new { iul.LoginProvider, iul.ProviderKey });
            modelBuilder.Entity<IdentityUserRole<Guid>>().HasKey(iur => new { iur.UserId, iur.RoleId });
            modelBuilder.Entity<IdentityUserToken<Guid>>().HasKey(iut => new { iut.UserId, iut.LoginProvider, iut.Name });

            modelBuilder.Entity<PartyWiseProduct>()
                .HasOne(pwp => pwp.Party)
                .WithMany()
                .HasForeignKey(pwp => pwp.PartyId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<PartyWiseProduct>()
                .HasOne(pwp => pwp.Product)
                .WithMany()
                .HasForeignKey(pwp => pwp.ProductId);             

            modelBuilder.Entity<ProductRate>()
                .HasOne(pr => pr.Product) // Specify the navigation property
                .WithMany() // Optional: can specify a navigation property in Product for related ProductRates
                .HasForeignKey(pr => pr.ProductId) // Specify the foreign key property
                .OnDelete(DeleteBehavior.Cascade); // Optional: specify delete behavior

            modelBuilder.Entity<Invoice>()
           .HasOne(pwp => pwp.Parties)
           .WithMany()
           .HasForeignKey(pwp => pwp.PartyId);

            modelBuilder.Entity<Invoice>()
                .HasOne(pwp => pwp.Product)
                .WithMany()
                .HasForeignKey(pwp => pwp.ProductId);
            modelBuilder.Entity<InvoiceEntry>()
.HasOne(pwp => pwp.Parties)
.WithMany()
.HasForeignKey(pwp => pwp.PartyId);

            modelBuilder.Entity<InvoiceEntry>()
                .HasOne(pwp => pwp.Product)
                .WithMany()
                .HasForeignKey(pwp => pwp.ProductId);
            modelBuilder.Entity<PartyTotal>()
     .HasOne(pt => pt.Party)
     .WithMany() // Specify if Party has a collection of PartyTotal records
     .HasForeignKey(pt => pt.PartyId)
     .OnDelete(DeleteBehavior.Restrict); // Use Restrict or Cascade as needed
        }
    }

}
