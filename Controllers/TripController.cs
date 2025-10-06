using Microsoft.AspNetCore.Mvc;
using aspapp.Models;
using aspapp.Services;
using System.Threading.Tasks;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace aspapp.Controllers
{
    [Route("trip")]
    public class TripController : Controller
    {
        private readonly ITripService _tripService;
        private readonly IGuideService _guideService;
        private readonly ITravelerService _travelerService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<TripController> _logger;

        public TripController(
            ITripService tripService,
            IGuideService guideService,
            ITravelerService travelerService,
            UserManager<IdentityUser> userManager,
            ILogger<TripController> logger)
        {
            _tripService = tripService;
            _guideService = guideService;
            _travelerService = travelerService;
            _userManager = userManager;
            _logger = logger;
        }

        [Authorize(Roles = "Admin,Guide")]
        [HttpGet("create")]
        public async Task<IActionResult> Create()
        {
            var model = new TripViewModel
            {
                Guides = await _guideService.GetAllGuides(),
                Travelers = await _travelerService.GetAllTravelers()
            };
            return View(model);
        }

        [Authorize(Roles = "Admin,Guide")]
        [HttpPost("create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(TripViewModel tripViewModel)
        {
            tripViewModel.Guides = await _guideService.GetAllGuides();
            tripViewModel.Travelers = await _travelerService.GetAllTravelers();

            if (ModelState.IsValid)
            {
                try
                {
                    await _tripService.AddTrip(tripViewModel);
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[Create] Failed to add trip.");
                    ModelState.AddModelError(string.Empty, "An unexpected error occurred while adding the trip.");
                }
            }

            foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
            {
                _logger.LogWarning("[Create] Validation error: {Message}", error.ErrorMessage);
            }

            return View(tripViewModel);
        }


        [Authorize(Roles = "Admin,Guide")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var trips = await _tripService.GetAllTrips();
            return View(trips);
        }


        [Authorize(Roles = "Admin,Guide")]
        [HttpGet("edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var trip = await _tripService.GetTripById(id);
            if (trip == null)
                return NotFound();

            trip.Guides = await _guideService.GetAllGuides();
            trip.Travelers = await _travelerService.GetAllTravelers();
            return View(trip);
        }

        [Authorize(Roles = "Admin,Guide")]
        [HttpPost("edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, TripViewModel tripViewModel)
        {
            if (id != tripViewModel.TripId)
                return BadRequest();

            if (ModelState.IsValid)
            {
                try
                {
                    await _tripService.UpdateTrip(tripViewModel);
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[Edit] Failed to update trip.");
                    ModelState.AddModelError(string.Empty, ex.Message);
                }
            }

            foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
            {
                _logger.LogWarning("[Edit] Validation error: {Message}", error.ErrorMessage);
            }

            tripViewModel.Guides = await _guideService.GetAllGuides();
            tripViewModel.Travelers = await _travelerService.GetAllTravelers();
            return View(tripViewModel);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var trip = await _tripService.GetTripById(id);
            if (trip == null)
                return NotFound();

            return View(trip);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("delete/{id}"), ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            try
            {
                await _tripService.DeleteTrip(id);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[Delete] Failed to delete trip.");
                return StatusCode(500, "Internal server error");
            }
        }

    }
}
