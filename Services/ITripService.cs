using aspapp.Models;
using aspapp.Models.VM;
using System.Linq;
using System.Threading.Tasks;

namespace aspapp.Services
{
    public interface ITripService
    {
        Task<List<TripViewModel>> GetAllTrips();  // Zwracamy model Trip, nie TripViewModel
        Task<TripViewModel> GetTripById(int tripId);  // Zwracamy model Trip, nie TripViewModel
        Task AddTrip(TripViewModel trip);  // Używamy modelu Trip
        Task UpdateTrip(TripViewModel trip);  // Używamy modelu Trip
        Task DeleteTrip(int tripId);  // Używamy TripId
    }
}
