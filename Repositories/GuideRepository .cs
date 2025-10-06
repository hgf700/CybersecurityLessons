using aspapp.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;

namespace aspapp.Repositories
{
    public class GuideRepository : IGuideRepository
    {
        private readonly TripContext _context;

        public GuideRepository(TripContext context)
        {
            _context = context;
        }

        // Pobiera wszystkich przewodników (bez śledzenia zmian - lepsza wydajność)
        public IQueryable<Guide> GetAllGuides(bool includeTrips = false)
        {
            var query = _context.Guides.AsQueryable();

            // Jeśli chcesz dołączyć podróże, używamy Include
            if (includeTrips)
            {
                query = query.Include(g => g.Trips);
            }

            return query.AsNoTracking(); // No tracking for better performance on read-only scenarios
        }

        // Pobiera przewodnika po ID (wraz z powiązanymi wycieczkami)
        public async Task<Guide?> GetGuideById(int guideId, bool includeTrips = false)
        {
            var query = _context.Guides.AsQueryable();

            // Jeśli chcesz dołączyć podróże, używamy Include
            if (includeTrips)
            {
                query = query.Include(g => g.Trips);
            }

            return await query.AsNoTracking() // No tracking for better performance
                               .FirstOrDefaultAsync(g => g.GuideId == guideId);
        }

        // Implementacja metody GetGuideByEmail
        public async Task<Guide?> GetGuideByEmail(string email)
        {
            return await _context.Guides
                .AsNoTracking() // No tracking for better performance
                .FirstOrDefaultAsync(g => g.Email == email);
        }

        // Dodaje nowego przewodnika
        public async Task AddGuide(Guide guide)
        {
            // Check if a guide with the same email already exists
            var existingGuide = await _context.Guides
                .FirstOrDefaultAsync(g => g.Email == guide.Email);

            if (existingGuide != null)
            {
                throw new InvalidOperationException("Przewodnik z tym emailem już istnieje.");
            }

            // Add the guide and save changes in one go
            await _context.Guides.AddAsync(guide);
            await _context.SaveChangesAsync(); // Save changes after addition
        }

        // Aktualizuje dane przewodnika po sprawdzeniu istnienia
        public async Task UpdateGuide(Guide guide)
        {
            // Check if the guide exists
            var existingGuide = await _context.Guides.FindAsync(guide.GuideId);
            if (existingGuide == null)
            {
                throw new KeyNotFoundException("Przewodnik nie został znaleziony.");
            }

            // Update existing guide data
            _context.Entry(existingGuide).CurrentValues.SetValues(guide);
            await _context.SaveChangesAsync(); // Save changes
        }

        // Usuwa przewodnika
        public async Task DeleteGuide(int guideId)
        {
            var guide = await _context.Guides.FindAsync(guideId);
            if (guide == null)
            {
                throw new KeyNotFoundException("Przewodnik nie został znaleziony.");
            }

            // Remove the guide and save changes
            _context.Guides.Remove(guide);
            await _context.SaveChangesAsync(); // Save changes
        }
    }
}
