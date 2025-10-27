using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using aspapp.ApplicationUser;

namespace aspapp.Models
{
    //ApplicationUser
    public class TripContext : IdentityDbContext<IdentityUser>
    {
        public TripContext(DbContextOptions<TripContext> options) : base(options) { }

        public DbSet<SecuritySettings> SecuritySettings { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

        }
    }

}
