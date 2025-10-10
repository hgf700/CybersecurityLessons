using Microsoft.AspNetCore.Mvc;
using aspapp.Models;
using aspapp.Repositories;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;


namespace aspapp.Controllers
{
    [Route("traveler")]
    public class TravelerController : Controller
    {
        private readonly ITravelerRepository _travelerService;
        private readonly UserManager<IdentityUser> _userManager;
        string[] roleNames = { "ADMIN", "User" };

        public TravelerController(ITravelerRepository travelerService, UserManager<IdentityUser> userManager)
        {
            _travelerService = travelerService;
            _userManager = userManager;
        }

        // Index GET
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpGet("create")]
        public IActionResult Create() => View();

        [AllowAnonymous]
        [HttpPost("create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Firstname,Lastname,Email,BirthDate")] Traveler traveler)
        {
            if (ModelState.IsValid)
            {
                var identityUser = new IdentityUser { UserName = traveler.Email, Email = traveler.Email, PasswordHash = traveler.Password };
                var result = await _userManager.CreateAsync(identityUser);

                if (result.Succeeded)
                {
                    await _travelerService.AddTraveler(traveler);
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                return View(traveler);

            }
            return View(traveler);
        }

        //[Authorize(Roles = "Admin,User")]
        [AllowAnonymous]
        [HttpGet("edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var traveler = await _travelerService.GetTravelerById(id);
            if (traveler == null) return NotFound();
            return View(traveler);
        }

        //[Authorize(Roles = "Admin,User")]
        [AllowAnonymous]
        [HttpPost("edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("TravelerId,Firstname,Lastname,Email,BirthDate")] Traveler traveler)
        {

            if (ModelState.IsValid)
            {
                await _travelerService.UpdateTraveler(traveler);
                return RedirectToAction(nameof(Index));
            }
            return View(traveler);
        }

        // Delete GET
        //[Authorize(Roles = "Admin")]
        [AllowAnonymous]
        [HttpGet("delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var traveler = await _travelerService.GetTravelerById(id);
            if (traveler == null) return NotFound();
            return View(traveler);
        }

        // Delete POST
        //[Authorize(Roles = "Admin")]
        [AllowAnonymous]
        [HttpPost("delete/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            await _travelerService.DeleteTraveler(id);
            return RedirectToAction(nameof(Index));
        }
    }
}
