using aspapp.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace aspapp.Repositories
{
    public interface ITripRepository
    {
        IQueryable<Trip> GetAllTrips();
        Task<Trip> GetTripById(int tripId);
        Task AddTrip(Trip trip);
        Task UpdateTrip(Trip trip);
        Task DeleteTrip(int tripId);
    }
}
