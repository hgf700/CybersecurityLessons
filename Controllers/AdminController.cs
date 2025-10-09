using Microsoft.AspNetCore.Mvc;
using aspapp.Repositories;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace aspapp.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("admin")]
    public class AdminController : Controller
    {

        private readonly ITravelerRepository _travelerService;


        public AdminController(

            ITravelerRepository travelerService)

        {

            _travelerService = travelerService;

        }

        // Strona główna panelu admina
        [HttpGet("")]
        public IActionResult Index()
        {
            return View(); // Możesz stworzyć panel z linkami do przewodników, podróżników, wycieczek
        }



        [HttpGet("travelers")]
        public IActionResult Travelers()
        {
            var travelers = _travelerService.GetAllTravelers();
            return View(travelers);
        }




        [HttpPost("delete-traveler/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteTraveler(int id)
        {
            await _travelerService.DeleteTraveler(id);
            return RedirectToAction(nameof(Travelers));
        }

    }
}
