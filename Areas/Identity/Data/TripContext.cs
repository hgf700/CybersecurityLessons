using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Models
{
    public class TripContext : IdentityDbContext<IdentityUser>
    {
        public DbSet<Traveler> Travelers { get; set; }

        public TripContext(DbContextOptions<TripContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);



            modelBuilder.Entity<Traveler>()
                .Property(t => t.TravelerId)
                .ValueGeneratedOnAdd();

        }
    }

}
