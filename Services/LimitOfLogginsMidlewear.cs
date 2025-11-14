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

        public async Task InvokeAsync(HttpContext http, UserManager<ApplicationUser> userManager, TripContext context)
        {
            if (http.Request.Path.StartsWithSegments("/Identity/Account/Login") &&
                http.Request.Method == HttpMethods.Post)
            {
                var form = http.Request.Form;
                var email = form["Input.Email"].ToString();
                var password = form["Input.Password"].ToString();
                if (!string.IsNullOrEmpty(email))
                {
                    var user = await userManager.Users.FirstOrDefaultAsync(u => u.Email == email);

                    if (user != null)
                    {
                        var securitySettings = await context.SecuritySettings.FirstOrDefaultAsync();
                        var limit = securitySettings.LimitOfWrongPasswords;
                        var blockTime = securitySettings.BlockTime;

                        var passwordValid = await userManager.CheckPasswordAsync(user, password);
                        if (!passwordValid) {
                            user.AccessFailedCount++;

                            if (user.AccessFailedCount >= limit)
                            {
                                user.LockoutEnd = DateTimeOffset.UtcNow.Add(TimeSpan.FromMinutes(blockTime));
                                user.AccessFailedCount = 0; // reset licznika po blokadzie
                            }
                            await userManager.UpdateAsync(user);
                        }
                        else
                        {
                            if (user.AccessFailedCount > 0)
                            {
                                user.AccessFailedCount = 0;
                                user.LockoutEnd = null;
                                await userManager.UpdateAsync(user);
                            }
                        }
                    }
                }
            }
            await _next(http);
        }
    }
}
