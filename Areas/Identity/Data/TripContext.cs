using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Models
{
    public class TripContext : IdentityDbContext<IdentityUser>
    {
        public DbSet<Traveler> Travelers { get; set; }
        public DbSet<Guide> Guides { get; set; }
        public DbSet<Trip> Trips { get; set; }

        public TripContext(DbContextOptions<TripContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Guide>()
                .Property(g => g.GuideId)
                .ValueGeneratedOnAdd();

            modelBuilder.Entity<Traveler>()
                .Property(t => t.TravelerId)
                .ValueGeneratedOnAdd();

            modelBuilder.Entity<Trip>()
                .HasOne(t => t.Guide)
                .WithMany(g => g.Trips)
                .HasForeignKey(t => t.GuideId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<Trip>()
                .HasOne(t => t.Traveler)
                .WithMany(t => t.Trips)
                .HasForeignKey(t => t.TravelerId)
                .OnDelete(DeleteBehavior.Restrict);

        }
    }

}
