using Microsoft.AspNetCore.Mvc;
using aspapp.Services;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace aspapp.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("admin")]
    public class AdminController : Controller
    {
        private readonly IGuideService _guideService;
        private readonly ITravelerService _travelerService;
        private readonly ITripService _tripService;

        public AdminController(
            IGuideService guideService,
            ITravelerService travelerService,
            ITripService tripService)
        {
            _guideService = guideService;
            _travelerService = travelerService;
            _tripService = tripService;
        }

        // Strona główna panelu admina
        [HttpGet("")]
        public IActionResult Index()
        {
            return View(); // Możesz stworzyć panel z linkami do przewodników, podróżników, wycieczek
        }

        // Lista wszystkich przewodników
        [HttpGet("guides")]
        public async Task<IActionResult> Guides()
        {
            var guides = await _guideService.GetAllGuides();
            return View(guides);
        }

        // Lista wszystkich podróżników
        [HttpGet("travelers")]
        public async Task<IActionResult> Travelers()
        {
            var travelers = await _travelerService.GetAllTravelers();
            return View(travelers);
        }

        // Lista wszystkich wycieczek
        //[HttpGet("trips")]
        //public async Task<IActionResult> Trips()
        //{
        //    var trips = await _tripService.GetAllTrips();
        //    return View(trips);
        //}

        // Możesz również dodać możliwość usuwania:
        [HttpPost("delete-guide/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteGuide(int id)
        {
            await _guideService.DeleteGuide(id);
            return RedirectToAction(nameof(Guides));
        }

        [HttpPost("delete-traveler/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteTraveler(int id)
        {
            await _travelerService.DeleteTraveler(id);
            return RedirectToAction(nameof(Travelers));
        }

        //[HttpPost("delete-trip/{id}")]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> DeleteTrip(int id)
        //{
        //    await _tripService.DeleteTrip(id);
        //    return RedirectToAction(nameof(Trips));
        //}
    }
}
