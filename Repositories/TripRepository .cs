using aspapp.Models;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Repositories
{
    public class TripRepository : ITripRepository
    {
        private readonly TripContext _context;

        public TripRepository(TripContext context)
        {
            _context = context;
        }


        public async Task AddTrip(Trip trip)
        {
            if (trip == null)
                throw new ArgumentNullException(nameof(trip));

            _context.Trips.Add(trip);
            await _context.SaveChangesAsync();


        }

        public IQueryable<Trip> GetAllTrips()
        {
            return _context.Trips
                .Include(t => t.Guide)
                .Include(t => t.Traveler);
        }

        public async Task<Trip?> GetTripById(int id)
        {
            return await _context.Trips
                .Include(t => t.Guide)
                .Include(t => t.Traveler)
                .FirstOrDefaultAsync(t => t.TripId == id);
        }

        public async Task UpdateTrip(Trip trip)
        {
            var existingTrip = await _context.Trips.FindAsync(trip.TripId);
            if (existingTrip == null)
                throw new KeyNotFoundException($"Trip with Id {trip.TripId} not found.");

            _context.Entry(existingTrip).CurrentValues.SetValues(trip);

            existingTrip.GuideId = trip.GuideId;
            existingTrip.TravelerId = trip.TravelerId;

            await _context.SaveChangesAsync();
        }

        public async Task DeleteTrip(int id)
        {
            var trip = await _context.Trips.FindAsync(id);
            if (trip == null)
                throw new KeyNotFoundException($"Trip with Id {id} not found");

            _context.Trips.Remove(trip);
            await _context.SaveChangesAsync();
        }


    }
}
