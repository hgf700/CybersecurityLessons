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

        [Authorize(Roles = "ADMIN")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var travelers = _travelerService.GetAllTravelers(); // <-- pewnie typ Traveler

            var travelerViewModels = travelers.Select(t => new TravelerViewModel
            {
                TravelerId = t.TravelerId,
                Email = t.Email
                // Password nie pokazujemy
            });

            return View(travelerViewModels); // <-- teraz poprawnie
        }


        [Authorize(Roles = "ADMIN")]
        [HttpGet("create")]
        public IActionResult Create() => View();



        [Authorize(Roles = "ADMIN")]
        [HttpPost("create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Email,Password,ConfirmPassword")] TravelerViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            //identity autoamtycznie hashuje
            var identityUser = new IdentityUser { UserName = model.Email, Email = model.Email};
            var result = await _userManager.CreateAsync(identityUser, model.Password); 

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(identityUser, "User");

                Traveler traveler = new Traveler()
                {
                    Email = model.Email,
                    Password = identityUser.PasswordHash 
                };

                await _travelerService.AddTraveler(traveler);

                return RedirectToAction(nameof(Index));
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View("Index"); 
        }


        [Authorize(Roles = "ADMIN")]
        [HttpGet("edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var traveler = await _travelerService.GetTravelerById(id);
            if (traveler == null) 
                return NotFound(); 

            var viewModel = new TravelerViewModel
            {
                TravelerId = traveler.TravelerId,
                Email = traveler.Email,
            };

            return View(viewModel);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("TravelerId,Email,Password,ConfirmPassword")] TravelerViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var traveler = await _travelerService.GetTravelerById(id);
            if (traveler == null)
                return NotFound();

            var identityUser = await _userManager.FindByEmailAsync(traveler.Email);
            if (identityUser == null)
                return NotFound();

            if (!string.IsNullOrEmpty(model.Password) && model.Password == model.ConfirmPassword)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);
                var passwordResult = await _userManager.ResetPasswordAsync(identityUser, token, model.Password);
                
                if (!passwordResult.Succeeded)
                {
                    foreach (var error in passwordResult.Errors)
                        ModelState.AddModelError("", error.Description);

                    return View(model);
                }
            }

            traveler.Email = model.Email;
            traveler.Password = identityUser.PasswordHash; 

            await _travelerService.UpdateTraveler(traveler);

            return RedirectToAction(nameof(Index));
        }


        [Authorize(Roles = "ADMIN")]
        [HttpGet("delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var traveler = await _travelerService.GetTravelerById(id);
            if (traveler == null) return NotFound();
            return View(traveler);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("delete/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            await _travelerService.DeleteTraveler(id);
            return RedirectToAction(nameof(Index));
        }
    }
}
