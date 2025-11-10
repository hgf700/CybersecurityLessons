using aspapp.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace aspapp.DbFactory
{
    public class TripContextFactory: IDesignTimeDbContextFactory<TripContext>
    {
        public TripContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var connectionString = configuration.GetConnectionString("DefaultConnection");

            var optionsBuilder = new DbContextOptionsBuilder<TripContext>();
            optionsBuilder.UseSqlServer(connectionString);

            return new TripContext(optionsBuilder.Options);
        }
    }
}
