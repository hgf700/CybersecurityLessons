using aspapp.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace aspapp.Repositories
{
    public class TravelerRepository : ITravelerRepository
    {
        private readonly TripContext _context;


        public TravelerRepository(TripContext context)
        {
            _context = context;
        }

        public IQueryable<Traveler> GetAllTravelers()
        {
            var query = _context.Travelers.AsNoTracking();
            return query;
        }

        //public async Task ChangePassword(string email,string OldPassword,string NewPassword)
        //{
        //    // Sprawdzamy, czy podróżnik o tym samym emailu już istnieje
        //    var existingTraveler = await _context.Travelers
        //        .FirstOrDefaultAsync(t => t.Email == email);

        //    if (existingTraveler != null)
        //    {
        //        throw new InvalidOperationException("Podróżnik z tym emailem już istnieje.");
        //    }

        //    await _context.Travelers.AddAsync(traveler);
        //    await _context.SaveChangesAsync();
        //}

        // Pobierz podróżnika po ID z wycieczkami
        public async Task<Traveler?> GetTravelerById(int travelerId)
        {
            var query = _context.Travelers.AsQueryable();

            return await query.AsNoTracking().FirstOrDefaultAsync(t => t.TravelerId == travelerId);
        }

        public async Task AddTraveler(TravelerViewModel model)
        {
            // Sprawdzamy, czy podróżnik o tym samym emailu już istnieje
            var existingTraveler = await _context.Travelers
                .FirstOrDefaultAsync(t => t.Email == model.Email);

            if (existingTraveler != null)
            {
                throw new InvalidOperationException("Podróżnik z tym emailem już istnieje.");
            }

            Traveler traveler = new Traveler
            {
                Email = model.Email,
                Password = model.Password 
            };

            await _context.Travelers.AddAsync(traveler);
            await _context.SaveChangesAsync();
        }

        // Zaktualizuj dane podróżnika (zabezpieczenie przed null)
        public async Task UpdateTraveler(Traveler traveler)
        {
            var existingTraveler = await _context.Travelers.FindAsync(traveler.TravelerId);
            if (existingTraveler == null)
            {
                throw new KeyNotFoundException("Podróżnik o podanym ID nie został znaleziony.");
            }

            // Zaktualizowanie wartości istniejącego podróżnika
            _context.Entry(existingTraveler).CurrentValues.SetValues(traveler);
            await _context.SaveChangesAsync();
        }

        // Usuń podróżnika
        public async Task DeleteTraveler(int travelerId)
        {
            var traveler = await _context.Travelers.FindAsync(travelerId);
            if (traveler == null)
            {
                throw new KeyNotFoundException("Podróżnik o podanym ID nie został znaleziony.");
            }

            _context.Travelers.Remove(traveler);
            await _context.SaveChangesAsync();
        }
    }
}
