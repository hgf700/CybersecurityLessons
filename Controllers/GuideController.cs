using Microsoft.AspNetCore.Mvc;
using aspapp.Models;
using aspapp.Services;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using aspapp.Models.VM;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace aspapp.Controllers
{
    [Route("guide")]
    public class GuideController : Controller
    {
        private readonly IGuideService _guideService;
        private readonly UserManager<IdentityUser> _userManager;
        string[] roleNames = { "Admin", "Guide", "User" };
        public GuideController(IGuideService guideService, UserManager<IdentityUser> userManager)
        {
            _guideService = guideService;
            _userManager = userManager;
        }

        // Index GET
        [Authorize(Roles = "Admin,Guide")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var guides = await _guideService.GetAllGuides();
            return View(guides);
        }

        // Create GET
        [Authorize(Roles = "Admin,Guide")]
        [HttpGet("create")]
        public IActionResult Create() => View();

        // Create POST
        [Authorize(Roles = "Admin,Guide")]
        [HttpPost("create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Firstname,Lastname,Email,Title")] GuideViewModel guideViewModel)
        {
            if (ModelState.IsValid)
            {

                var passworddef = "asd123A!";
                var identityUser = new IdentityUser { UserName = guideViewModel.Email, Email = guideViewModel.Email, PasswordHash = passworddef };
                var result = await _userManager.CreateAsync(identityUser);

                if (result.Succeeded || ModelState.IsValid) //nwm
                {
                    await _userManager.AddToRoleAsync(identityUser, roleNames[1]);
                    await _guideService.AddGuide(guideViewModel); 
                    return RedirectToAction(nameof(Index));
                }
            }
            return View(guideViewModel);
        }
        

        [Authorize(Roles = "Admin,Guide")]
        [HttpGet("edit/{id}")]
        public async Task<IActionResult> Edit(int id)
        {
            var guide = await _guideService.GetGuideById(id);
            if (guide == null) return NotFound();
            return View(guide); // Assuming guide is GuideViewModel or equivalent
        }

        [Authorize(Roles = "Admin,Guide")]
        [HttpPost("edit/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("GuideId,Firstname,Lastname,Email,BirthDate")] GuideViewModel guideViewModel)
        {
            if (id != guideViewModel.GuideId) return BadRequest();

            if (ModelState.IsValid)
            {
                await _guideService.UpdateGuide(guideViewModel); // Assuming this method accepts GuideViewModel
                return RedirectToAction(nameof(Index));
            }
            return View(guideViewModel);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            var guide = await _guideService.GetGuideById(id);
            if (guide == null) return NotFound();
            return View(guide); // Assuming guide is GuideViewModel or equivalent
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("delete/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            await _guideService.DeleteGuide(id);
            return RedirectToAction(nameof(Index));
        }
    }
}
