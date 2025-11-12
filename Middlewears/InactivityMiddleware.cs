using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using aspapp.ApplicationUse;
using aspapp.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace aspapp.Middlewears
{
    public class InactivityMiddleware
    {
        private readonly RequestDelegate _next;

        public InactivityMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Pobranie scoped serwisów wewnątrz InvokeAsync
            var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
            var db = context.RequestServices.GetRequiredService<TripContext>();

            if (context.User?.Identity?.IsAuthenticated == true &&
                !context.Request.Path.StartsWithSegments("/Identity/Account/Login"))
            {
                var user = await userManager.GetUserAsync(context.User);

                if (user != null)
                {
                    var settings = await db.SecuritySettings.FirstOrDefaultAsync();
                    var timeout = TimeSpan.FromMinutes(settings?.TimeOfInactivity ?? 10);

                    if (user.LastActivity.HasValue)
                    {
                        var inactivity = DateTime.UtcNow - user.LastActivity.Value;
                        if (inactivity > timeout)
                        {
                            await context.SignOutAsync();
                            context.Response.Redirect("/Identity/Account/Login?reason=timeout");
                            return;
                        }
                    }

                    user.LastActivity = DateTime.UtcNow;
                    await userManager.UpdateAsync(user);
                }
            }

            await _next(context);
        }
    }
}
