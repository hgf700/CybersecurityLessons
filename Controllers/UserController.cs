using aspapp.Models;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Controllers
{
    [Authorize(Roles = "User")]
    [Route("user")]
    public class UserController : Controller
    {
        private readonly UserManager<aspapp.ApplicationUser.ApplicationUse> _userManager;
        private readonly SignInManager<aspapp.ApplicationUser.ApplicationUse> _signInManager;
        private readonly TripContext _tripContext;
        private readonly ILogger<UserController> _logger;

        string[] roleNames = { "ADMIN", "User" };

        public UserController(UserManager<aspapp.ApplicationUser.ApplicationUse> userManager,
                              SignInManager<ApplicationUser.ApplicationUse> signInManager,
                              TripContext tripContext,
                              ILogger<UserController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tripContext = tripContext;
            _logger = logger;
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

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound("Użytkownik nie został znaleziony.");

            var passwordValid = await _userManager.CheckPasswordAsync(user, model.OldPassword);
            if (!passwordValid)
            {
                ModelState.AddModelError(string.Empty, "Niepoprawne obecne hasło.");
                _logger.LogInformation("Status: {Status}, Action: {Action}, target {TargetUser} Time: {Time}",
                    "Failed",
                    "EditPasswordUser",
                    user?.Email ?? "unknown",
                    DateTime.UtcNow);

                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                _logger.LogInformation("Status: {Status}, Action: {Action}, target {TargetUser} Time: {Time}",
                    "Failed",
                    "EditPasswordUser",
                    user.Email,
                    DateTime.UtcNow);

                return View(model);
            }

            user.LastPasswordChangeDate = DateTime.UtcNow;

            var settings = await _tripContext.SecuritySettings.FirstOrDefaultAsync();
            if (settings != null)
                ; //user.PasswordExpirationDate = DateTime.UtcNow.AddMinutes(1);

            await _tripContext.PasswordHistories.AddAsync(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash
            });

            await _tripContext.SaveChangesAsync();

            await _signInManager.RefreshSignInAsync(user);

            _logger.LogInformation("Status: {Status}, Action: {Action}, target {TargetUser} Time: {Time}",
                "Success",
                "EditPasswordUser",
                user.Email,
                DateTime.UtcNow);

            ViewBag.Message = "Hasło zostało pomyślnie zmienione.";
            return View("Index");
        }
    }
}
