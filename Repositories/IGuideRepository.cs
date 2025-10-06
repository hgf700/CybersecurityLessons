using aspapp.Models;
using System.Threading.Tasks;

namespace aspapp.Repositories
{
    public interface IGuideRepository
    {
        IQueryable<Guide> GetAllGuides(bool includeTrips = false);  // Include parameter for trips
        Task<Guide?> GetGuideById(int guideId, bool includeTrips = false);  // Include parameter for trips
        Task<Guide?> GetGuideByEmail(string email);  // Add method to get guide by email
        Task AddGuide(Guide guide);
        Task UpdateGuide(Guide guide);
        Task DeleteGuide(int guideId);
    }
}
