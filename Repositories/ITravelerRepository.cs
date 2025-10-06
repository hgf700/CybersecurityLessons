using aspapp.Models;

namespace aspapp.Repositories
{
    public interface ITravelerRepository
    {
        IQueryable<Traveler> GetAllTravelers(bool includeTrips = false);  // Zaktualizowany interfejs z parametrem includeTrips
        Task<Traveler?> GetTravelerById(int travelerId, bool includeTrips = false);  // Zaktualizowany interfejs z parametrem includeTrips
        Task AddTraveler(Traveler traveler);
        Task UpdateTraveler(Traveler traveler);
        Task DeleteTraveler(int travelerId);
    }
}
