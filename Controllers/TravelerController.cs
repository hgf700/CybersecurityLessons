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

        [Authorize(Roles = "User")]
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


        [Authorize(Roles = "User")]
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

            traveler.Password = identityUser.PasswordHash;

            await _travelerService.UpdateTraveler(traveler);

            return RedirectToAction(nameof(Index));
        }

    }
}
