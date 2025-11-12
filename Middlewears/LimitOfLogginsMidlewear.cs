using aspapp.ApplicationUse;
using aspapp.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace aspapp.Middlewears
{
    public class LimitOfLogginsMiddleware
    {
        private readonly RequestDelegate _next;

        public LimitOfLogginsMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager, TripContext db)
        {
            if (context.Request.Path.StartsWithSegments("/Identity/Account/Login") &&
                context.Request.Method == HttpMethods.Post)
            {
                // Pobierz dane z formularza logowania
                var form = context.Request.Form;
                var email = form["Input.Email"].ToString();

                if (!string.IsNullOrEmpty(email))
                {
                    var user = await userManager.Users.FirstOrDefaultAsync(u => u.Email == email);

                    if (user != null)
                    {
                        var securitySettings = await db.SecuritySettings.FirstOrDefaultAsync();
                        var limit = securitySettings.LimitOfWrongPasswords;
                        var blockTime = securitySettings.BlockTime;

                        
                    }
                }
            }

            await _next(context);
        }
    }
}
