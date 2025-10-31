using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace aspapp.Controllers
{
    [Authorize(Roles = "ADMIN")]
    [Route("admin")]
    public class AdminController : Controller
    {

        private readonly UserManager<aspapp.ApplicationUser.ApplicationUse> _userManager;
        string[] roleNames = { "ADMIN", "User" };

        public AdminController(  UserManager<aspapp.ApplicationUser.ApplicationUse> userManager)
        {
            _userManager = userManager;
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            ViewBag.Message = $"Zalogowano jako {user.Email}";

            // Pobranie wszystkich użytkowników
            var userList = new List<UserWithRoleViewModel>();

            var allUsers = _userManager.Users.ToList();

            foreach (var u in allUsers)
            {
                var roles = await _userManager.GetRolesAsync(u);
                userList.Add(new UserWithRoleViewModel
                {
                    Id = u.Id,
                    Email = u.Email,
                    UserName = u.UserName,
                    Roles = roles.ToList()
                });
            }

            return View(userList);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("CreateUser")]
        public async Task<IActionResult> CreateUser()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("CreateUser")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(CreateUser model)
        {
            if (!ModelState.IsValid)
                return View();

            var targetUser = await _userManager.FindByEmailAsync(model.Email);
            if (targetUser != null)
            {
                ModelState.AddModelError(string.Empty, "Użytkownik o podanym adresie e-mail nie istnieje.");
                return View(model);
            }

            if (model.Password != model.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "hasła nie są takie same.");
                return View(model);
            }

            var identityUser = new aspapp.ApplicationUser.ApplicationUse
            {
                UserName = model.Email,
                Email = model.Email,
                LockoutEnabled = true,
                MustChangePassword = true 
            };

            var result = await _userManager.CreateAsync(identityUser, model.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(identityUser, "User");
                TempData["Message"] = "Użytkownik został utworzony.";
                return RedirectToAction(nameof(Index));
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View("Index");
            //return View(model);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("EditAdminPassword")]
        public async Task<IActionResult> EditAdminPassword()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("EditAdminPassword")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditAdminPassword(EditPassword model)
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

            if (model.NewPassword != model.ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Nowe hasła nie są takie same.");
                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return View(model);
            }

            // Opcjonalnie: komunikat o sukcesie
            ViewBag.Message = "Hasło zostało pomyślnie zmienione.";

            return View("Index");
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("EditAdmin")]
        public async Task<IActionResult> EditAdmin()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("EditAdmin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditAdmin(EditAdmin model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            // Sprawdzenie, czy nowa nazwa użytkownika lub e-mail są już zajęte
            var existingUserByName = await _userManager.FindByNameAsync(model.UserName);

            if (existingUserByName != null && existingUserByName.Id != user.Id)
            {
                ModelState.AddModelError("UserName", "Ta nazwa użytkownika jest już zajęta.");
                return View(model);
            }

            // Zmiana danych użytkownika
            user.UserName = model.UserName;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                foreach (var error in updateResult.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return View(model);
            }

            ViewBag.Message = "Dane administratora zostały pomyślnie zaktualizowane.";
            return View(model);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("BlockAccount")]
        public async Task<IActionResult> BlockAccount()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("BlockAccount")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> BlockAccount(BlockAccount model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // Pobranie zalogowanego admina (tylko dla sprawdzenia)
            var admin = await _userManager.GetUserAsync(User);
            if (admin == null)
                return NotFound("Zalogowany administrator nie został znaleziony.");

            // Szukamy użytkownika po adresie e-mail
            var targetUser = await _userManager.FindByEmailAsync(model.Email);
            if (targetUser == null)
            {
                ModelState.AddModelError(string.Empty, "Użytkownik o podanym adresie e-mail nie istnieje.");
                return View(model);
            }

            if (admin.Id == targetUser.Id)
            {
                ModelState.AddModelError(string.Empty, "Nie możesz zablokować własnego konta administracyjnego.");
                return View();
            }

            var daysToBlock = model.Days > 0 ? model.Days : 30;

            // Ustawienie blokady
            await _userManager.SetLockoutEndDateAsync(targetUser, DateTimeOffset.UtcNow.AddDays(daysToBlock));
            await _userManager.UpdateAsync(targetUser);

            ViewBag.Message = $"Użytkownik {targetUser.Email} został zablokowany na {daysToBlock} dni.";

            return View(model);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("DeleteAccount")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAccount(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                ModelState.AddModelError(string.Empty, "Adres e-mail jest wymagany.");
                return View();
            }

            // Pobierz aktualnie zalogowanego admina (tylko dla walidacji)
            var admin = await _userManager.GetUserAsync(User);
            if (admin == null)
                return NotFound("Zalogowany administrator nie został znaleziony.");

            // Znajdź użytkownika po e-mailu
            var targetUser = await _userManager.FindByEmailAsync(email);
            if (targetUser == null)
            {
                ModelState.AddModelError(string.Empty, $"Użytkownik o adresie {email} nie istnieje.");
                return View();
            }

            // Zabezpieczenie: admin nie może usunąć samego siebie
            if (admin.Id == targetUser.Id)
            {
                ModelState.AddModelError(string.Empty, "Nie możesz usunąć własnego konta administracyjnego.");
                return View();
            }

            // Usuń użytkownika
            var result = await _userManager.DeleteAsync(targetUser);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return View();
            }

            ViewBag.Message = $"Użytkownik {targetUser.Email} został pomyślnie usunięty.";
            return View();
        }

    }
}
