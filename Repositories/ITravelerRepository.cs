using aspapp.Models;

namespace aspapp.Repositories
{
    public interface ITravelerRepository
    {
        IQueryable<Traveler> GetAllTravelers();  
        Task<Traveler?> GetTravelerById(int travelerId);
        Task AddTraveler(Traveler traveler);
        Task UpdateTraveler(Traveler traveler);
        Task DeleteTraveler(int travelerId);
    }
}
