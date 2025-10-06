using aspapp.Models.VM;

namespace aspapp.Services
{
    public interface ITravelerService
    {
        Task<List<TravelerViewModel>> GetAllTravelers(); // Returns a list of TravelerViewModel
        Task<TravelerViewModel> GetTravelerById(int travelerId);
        Task AddTraveler(TravelerViewModel traveler);
        Task UpdateTraveler(TravelerViewModel traveler);
        Task DeleteTraveler(int travelerId);
    }
}
