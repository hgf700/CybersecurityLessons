using Microsoft.AspNetCore.Authentication;

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
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var lastActivity = context.Session.GetString("LastActivity");
                var now = DateTime.UtcNow;

                if (lastActivity != null)
                {
                    var lastTime = DateTime.Parse(lastActivity);

                    // Sprawdź, czy użytkownik był nieaktywny zbyt długo
                    if (now - lastTime > _timeout)
                    {
                        await context.SignOutAsync(); // wyloguj użytkownika
                        context.Session.Clear();
                        context.Response.Redirect("/Account/Login?reason=timeout");
                        return;
                    }
                }

                // Zaktualizuj znacznik czasu
                context.Session.SetString("LastActivity", now.ToString("O"));
            }

            await _next(context);
        }
    }
}
