using aspapp.Models;
using aspapp.Models;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace aspapp.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<aspapp.ApplicationUser.ApplicationUse> _userManager;
        private readonly SignInManager<aspapp.ApplicationUser.ApplicationUse> _signInManager;
        string[] roleNames = { "ADMIN", "User" };

        public UserController(  UserManager<aspapp.ApplicationUser.ApplicationUse> userManager,
            SignInManager<ApplicationUser.ApplicationUse> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [Authorize(Roles = "User")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(); 
        }

        [Authorize(Roles = "User")]
        [HttpGet("EditPasswordUser")]
        public async Task<IActionResult> EditPasswordUser()
        {
            return View();
        }

        [Authorize(Roles = "User")]
        [HttpPost("EditPasswordUser")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditPasswordUser(EditPassword model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // Pobranie aktualnego użytkownika
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            // Sprawdzenie poprawności aktualnego hasła
            var passwordValid = await _userManager.CheckPasswordAsync(user, model.OldPassword);
            if (!passwordValid)
            {
                ModelState.AddModelError(string.Empty, "Niepoprawne obecne hasło.");
                return View(model);
            }

            // Próba zmiany hasła
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return View(model);
            }

            // Opcjonalnie: komunikat o sukcesie
            ViewBag.Message = "Hasło zostało pomyślnie zmienione.";

            await _signInManager.RefreshSignInAsync(user);

            return View("Index");
            //return View(model);
        }

    }
}