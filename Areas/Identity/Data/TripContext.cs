using aspapp.ApplicationUser;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Models
{
    public class TripContext : IdentityDbContext<ApplicationUse>
    {
        public TripContext(DbContextOptions<TripContext> options) : base(options) { }

        public DbSet<SecuritySettings> SecuritySettings { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
    }

}
