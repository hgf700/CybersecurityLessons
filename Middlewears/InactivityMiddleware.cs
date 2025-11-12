using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace aspapp.Middlewears
{
    public class InactivityMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TimeSpan _timeout;

        public InactivityMiddleware(RequestDelegate next, TimeSpan timeout)
        {
            _next = next;
            _timeout = timeout;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Nie sprawdzaj, jeśli użytkownik nie jest zalogowany lub wchodzi na stronę logowania
            if (context.User?.Identity?.IsAuthenticated == true &&
                !context.Request.Path.StartsWithSegments("/Account/Login"))
            {
                var now = DateTime.UtcNow;
                var lastActivityStr = context.Session.GetString("LastActivity");

                if (!string.IsNullOrEmpty(lastActivityStr) &&
                    DateTime.TryParse(lastActivityStr, out var lastActivity))
                {
                    var inactivityDuration = now - lastActivity;

                    if (inactivityDuration > _timeout)
                    {
                        // Zbyt długa bezczynność — wyloguj
                        await context.SignOutAsync();
                        context.Session.Clear();
                        context.Response.Redirect("/Account/Login?reason=timeout");
                        return;
                    }
                }

                // Zaktualizuj czas ostatniej aktywności
                context.Session.SetString("LastActivity", now.ToString("O"));
            }

            await _next(context);
        }
    }
}
