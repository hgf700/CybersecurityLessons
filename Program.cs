using aspapp.ApplicationUser;
using aspapp.ExtraTools;
using aspapp.Models;
using aspapp.Validator;
using AutoMapper;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using System.Globalization;

var builder = WebApplication.CreateBuilder(args);

// --- KONFIGURACJA BAZY DANYCH ---
builder.Services.AddDbContext<TripContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// --- LOKALIZACJA I WIDOKI ---
builder.Services.AddControllersWithViews()
    .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix);

builder.Services.AddLocalization(options =>
{
    options.ResourcesPath = "Resources";
});

builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supportedcultures = new[]
    {
        new CultureInfo("en-US"),
        new CultureInfo("pl-PL"),
    };
    options.DefaultRequestCulture = new RequestCulture("pl-PL");
    options.SupportedCultures = supportedcultures;
    options.SupportedUICultures = supportedcultures;
});

// --- FLUENT VALIDATION ---
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();

// --- AUTOMAPPER ---
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

// --- RAZOR PAGES ---
builder.Services.AddRazorPages();

// --- IDENTITY ---
builder.Services.AddIdentity<ApplicationUse, IdentityRole>(options =>
{
    // 🔐 Ustawienia hasła (możesz dostosować)
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 4;

    // 🔒 Lockout (blokada)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // 👤 Ustawienia użytkownika
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = false;

    // 🔑 Nie wymaga potwierdzenia konta
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<TripContext>()
.AddDefaultTokenProviders()
.AddDefaultUI();

// --- WALIDATOR HASŁA DYNAMICZNY ---
builder.Services.AddTransient<IPasswordValidator<ApplicationUse>, DynamicPasswordValidator<ApplicationUse>>();

// --- FAKE EMAIL SENDER ---
builder.Services.AddTransient<IEmailSender, NullEmailSender>();

// --- KONFIGURACJA COOKIE ---
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);

    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.LogoutPath = "/Identity/Account/Logout";
    options.SlidingExpiration = true;
});

var app = builder.Build();

// --- USTAWIENIA REQUEST LOCALIZATION ---
app.UseRequestLocalization();

// --- INICJALIZACJA BAZY (SecuritySettings + Role) ---
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<TripContext>();
    context.Database.Migrate();

    // Dodanie domyślnych SecuritySettings, jeśli nie istnieją
    if (!context.SecuritySettings.Any())
    {
        context.SecuritySettings.Add(new SecuritySettings
        {
            RequiredLength = 4,
            RequireDigit = false,
            RequireUppercase = false,
            RequireNonAlphanumeric = false,
            RequireLowercase = false
        });
        context.SaveChanges();
    }

    // Dodanie ról (ADMIN, User)
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roleNames = { "ADMIN", "User" };

    foreach (var roleName in roleNames)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

// --- ŚRODOWISKO ---
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// --- PIPELINE ---
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
