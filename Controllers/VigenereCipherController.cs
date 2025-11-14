using aspapp.Models;
using aspapp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using static System.Net.Mime.MediaTypeNames;


namespace aspapp.Controllers
{
    public class VigenereCipherController : Controller
    {
        private readonly UserManager<aspapp.ApplicationUse.ApplicationUser> _userManager;

        public VigenereCipherController(UserManager<aspapp.ApplicationUse.ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        private const string key = "TAJNE";

        [HttpGet]
        public IActionResult Activate()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Activate(string licenseKey)
        {
            string decrypted = VigenereCipher.Decipher(licenseKey, key);

            if (decrypted == "FULL_VERSION")
            {
                var user = await _userManager.GetUserAsync(User);
                user.Licence = "full_version";
                await _userManager.UpdateAsync(user);

                ViewBag.Message = "Licencja aktywowana! Masz pełną wersję.";
            }
            else
            {
                ViewBag.Message = "❌ Nieprawidłowy klucz licencyjny.";
            }

            return View();
        }
    }
}

