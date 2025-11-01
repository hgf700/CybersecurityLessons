using aspapp.Models;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace aspapp.Controllers
{
    [Authorize(Roles = "ADMIN")]
    [Route("admin")]
    public class AdminController : Controller
    {
        private readonly SignInManager<aspapp.ApplicationUser.ApplicationUse> _signInManager;
        private readonly UserManager<aspapp.ApplicationUser.ApplicationUse> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly TripContext _context;
        string[] roleNames = { "ADMIN", "User" };
        public AdminController(  UserManager<aspapp.ApplicationUser.ApplicationUse> userManager, 
            SignInManager<ApplicationUser.ApplicationUse> signInManager,
            IEmailSender emailSender,
            TripContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _context = context;
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
            {
                foreach (var e in ModelState.Values.SelectMany(v => v.Errors))
                    Console.WriteLine($"❌ {e.ErrorMessage}");
            }

            var targetUser = await _userManager.FindByEmailAsync(model.Email);

            if (targetUser != null)
            {
                ModelState.AddModelError(string.Empty, "Użytkownik o podanym adresie e-mail już istnieje.");
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
                Email = model.Email 
            };

            var result = await _userManager.CreateAsync(identityUser, model.Password);

            await _userManager.SetLockoutEndDateAsync(identityUser, null);
            await _userManager.ResetAccessFailedCountAsync(identityUser);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    Console.WriteLine($"[Identity] {error.Code}: {error.Description}");
                    ModelState.AddModelError(string.Empty, error.Description);
                }

            }

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(identityUser, "User");
                TempData["Message"] = "Użytkownik został utworzony.";

                var user = await _userManager.FindByEmailAsync(model.Email);
                string returnUrl = Url.Content("~/admin"); // strona główna
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ConfirmEmail",
                    pageHandler: null,
                    values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return RedirectToPage("RegisterConfirmation", new { email = model.Email, returnUrl = returnUrl });
                }
                else
                {
                    //await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
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

            await _signInManager.RefreshSignInAsync(user);

            TempData["Message"] = "Hasło zostało pomyślnie zmienione.";
            return RedirectToAction("Index");
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

            var isLocked = await _userManager.IsLockedOutAsync(targetUser);

            if (isLocked)
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(targetUser);
                return Content($"Użytkownik jest zablokowany do: {lockoutEnd?.LocalDateTime}");
                ViewBag.Message = $"Użytkownik jest zablokowany do: {lockoutEnd?.LocalDateTime}";
            }
            else
            {
                return Content("Użytkownik NIE jest zablokowany.");
                ViewBag.Message = "Użytkownik NIE jest zablokowany.";
            }

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
        public async Task<IActionResult> DeleteAccount(DeleteAccount model)
        {

            // Pobierz aktualnie zalogowanego admina (tylko dla walidacji)
            var admin = await _userManager.GetUserAsync(User);
            if (admin == null)
                return NotFound("Zalogowany administrator nie został znaleziony.");

            // Znajdź użytkownika po e-mailu
            var targetUser = await _userManager.FindByEmailAsync(model.email);
            if (targetUser == null)
            {
                ModelState.AddModelError(string.Empty, $"Użytkownik o adresie {model.email} nie istnieje.");
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
                {
                    Console.WriteLine($"[Identity] {error.Code}: {error.Description}");
                    ModelState.AddModelError(string.Empty, error.Description);
                }

            }

            if (result.Succeeded)
            {
                TempData["Message"] = "Użytkownik został usuniety.";
                return RedirectToAction(nameof(Index));
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            ViewBag.Message = $"Użytkownik {targetUser.Email} został pomyślnie usunięty.";

            return View(model);
        }

        [Authorize(Roles = "ADMIN")]
        [HttpGet("PasswordRequirments")]
        public async Task<IActionResult> PasswordRequirments()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        [HttpPost("PasswordRequirments")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PasswordRequirments(SecuritySettings model)
        {
            if (!ModelState.IsValid)
            {
                foreach (var e in ModelState.Values.SelectMany(v => v.Errors))
                    Console.WriteLine($"❌ {e.ErrorMessage}");
                return View(model);
            }

            var admin = await _userManager.GetUserAsync(User);
            if (admin == null)
                return NotFound("Zalogowany administrator nie został znaleziony.");

            // 🔍 Sprawdź, czy już istnieje rekord polityki
            var existingPolicy = await _context.SecuritySettings.FirstOrDefaultAsync();

            if (existingPolicy != null)
            {
                // 🔁 Nadpisz istniejącą politykę
                existingPolicy.RequiredLength = model.RequiredLength;
                existingPolicy.RequireDigit = model.RequireDigit;
                existingPolicy.RequireUppercase = model.RequireUppercase;
                existingPolicy.RequireLowercase = model.RequireLowercase;
                existingPolicy.RequireNonAlphanumeric = model.RequireNonAlphanumeric;
                existingPolicy.PasswordValidity = model.PasswordValidity;

                _context.SecuritySettings.Update(existingPolicy);
            }
            else
            {
                // 🆕 Utwórz nową politykę (np. o Id = 1)
                var policy = new SecuritySettings
                {
                    Id = 1,
                    RequiredLength = model.RequiredLength,
                    RequireDigit = model.RequireDigit,
                    RequireUppercase = model.RequireUppercase,
                    RequireLowercase = model.RequireLowercase,
                    RequireNonAlphanumeric = model.RequireNonAlphanumeric,
                    PasswordValidity = model.PasswordValidity
                };

                await _context.SecuritySettings.AddAsync(policy);
            }

            var changes = await _context.SaveChangesAsync();

            if (changes > 0)
            {
                TempData["Message"] = "✅ Polityka haseł została zapisana pomyślnie.";
                return RedirectToAction(nameof(PasswordRequirments));
            }

            ModelState.AddModelError(string.Empty, "⚠️ Nie udało się zapisać zmian w bazie danych.");
            return View(model);
        }


    }
}
