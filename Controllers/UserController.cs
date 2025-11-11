using aspapp.Models;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Serilog.Context;

namespace aspapp.Controllers
{
    [Authorize(Roles = "User")]
    [Route("user")]
    public class UserController : Controller
    {
        private readonly UserManager<aspapp.ApplicationUse.ApplicationUser> _userManager;
        private readonly SignInManager<aspapp.ApplicationUse.ApplicationUser> _signInManager;
        private readonly TripContext _tripContext;
        private readonly ILogger<UserController> _logger;

        string[] roleNames = { "ADMIN", "User" };

        public UserController(UserManager<aspapp.ApplicationUse.ApplicationUser> userManager,
                              SignInManager<ApplicationUse.ApplicationUser> signInManager,
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
            using (LogContext.PushProperty("Action", "Accessed User Index"))
            using (LogContext.PushProperty("Role", "User"))
            {
                _logger.LogInformation("User accessed the User Index page.");
            }

            return View();
        }

        [Authorize(Roles = "User")]
        [HttpGet("EditPasswordUser")]
        public async Task<IActionResult> EditPasswordUser()
        {
            using (LogContext.PushProperty("Action", "Accessed EditPasswordUser view"))
            using (LogContext.PushProperty("Role", "User"))
            {
                _logger.LogInformation("User accessed EditPasswordUser page.");
            }

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
            {
                using (LogContext.PushProperty("Action", "EditPasswordUser failed - user not found"))
                using (LogContext.PushProperty("Role", "User"))
                {
                    _logger.LogWarning("Attempt to change password failed because user not found.");
                }
                return NotFound("Użytkownik nie został znaleziony.");
            }

            var passwordValid = await _userManager.CheckPasswordAsync(user, model.OldPassword);
            if (!passwordValid)
            {
                ModelState.AddModelError(string.Empty, "Niepoprawne obecne hasło.");

                using (LogContext.PushProperty("Action", "EditPasswordUser failed - incorrect current password"))
                using (LogContext.PushProperty("Role", "User"))
                {
                    _logger.LogInformation("Password change attempt failed for {User}", user.Email);
                }

                return View(model);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                using (LogContext.PushProperty("Action", "EditPasswordUser failed - validation errors"))
                using (LogContext.PushProperty("Role", "User"))
                {
                    _logger.LogWarning("Password change failed for {User}", user.Email);
                }

                return View(model);
            }

            // Zapisz historię zmian haseł
            user.LastPasswordChangeDate = DateTime.UtcNow;
            await _tripContext.PasswordHistories.AddAsync(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash
            });
            await _tripContext.SaveChangesAsync();
            await _signInManager.RefreshSignInAsync(user);

            using (LogContext.PushProperty("Action", "EditPasswordUser succeeded"))
            using (LogContext.PushProperty("Role", "User"))
            {
                _logger.LogInformation("Password changed successfully for {User}", user.Email);
            }

            ViewBag.Message = "Hasło zostało pomyślnie zmienione.";
            return View("Index");
        }
    }
}
