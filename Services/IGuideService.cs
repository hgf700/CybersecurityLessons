using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using aspapp.Models.VM;

namespace aspapp.Services
{
    public interface IGuideService
    {
        Task<List<GuideViewModel>> GetAllGuides(); // Get all guides as a list of ViewModel

        Task<GuideViewModel> GetGuideById(int guideId); // Get a specific guide by ID

        Task AddGuide(GuideViewModel guide); // Add a new guide

        Task UpdateGuide(GuideViewModel guide); // Update an existing guide

        Task DeleteGuide(int id); // Delete a guide by ID
    }
}
