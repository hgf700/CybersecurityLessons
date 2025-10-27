using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using aspapp.Models; // Twój TripContext

namespace aspapp.Validator
{
    public class DynamicPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : IdentityUser
    {
        private readonly TripContext _context;

        public DynamicPasswordValidator(TripContext context)
        {
            _context = context;
        }

        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            // Pobranie ustawień z bazy
            var settings = await _context.SecuritySettings.FirstOrDefaultAsync();
            if (settings == null)
            {
                // Jeśli brak ustawień w bazie, zwracamy IdentityResult.Success
                return IdentityResult.Success;
            }

            var errors = new List<IdentityError>();

            if (password.Length < settings.RequiredLength)
                errors.Add(new IdentityError { Description = $"Hasło musi mieć co najmniej {settings.RequiredLength} znaków." });

            if (settings.RequireDigit && !password.Any(char.IsDigit))
                errors.Add(new IdentityError { Description = "Hasło musi zawierać cyfrę." });

            if (settings.RequireLowercase && !password.Any(char.IsLower))
                errors.Add(new IdentityError { Description = "Hasło musi zawierać małą literę." });

            if (settings.RequireUppercase && !password.Any(char.IsUpper))
                errors.Add(new IdentityError { Description = "Hasło musi zawierać wielką literę." });

            if (settings.RequireNonAlphanumeric && password.All(char.IsLetterOrDigit))
                errors.Add(new IdentityError { Description = "Hasło musi zawierać znak specjalny." });

            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }

    }
}
