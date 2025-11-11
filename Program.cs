using aspapp.ApplicationUse;
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
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;
using System.Collections.ObjectModel;
using System.Globalization;


var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

var columnOptions = new ColumnOptions();
columnOptions.Store.Remove(StandardColumn.Properties); // opcjonalnie, jeśli nie chcesz kolumn JSON
columnOptions.AdditionalColumns = new Collection<SqlColumn>
{
    new SqlColumn { ColumnName = "Role", DataType = System.Data.SqlDbType.NVarChar, DataLength = 100 },
    new SqlColumn { ColumnName = "Action", DataType = System.Data.SqlDbType.NVarChar, DataLength = 100 }
};

builder.Services.AddDbContext<TripContext>(options =>
    options.UseSqlServer(connectionString));


Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.File(
        "Logs/log.txt",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}"
    )
    .WriteTo.MSSqlServer(
        connectionString: connectionString,
        sinkOptions: new MSSqlServerSinkOptions
        {
            TableName = "Logs",
            AutoCreateSqlTable = true
        },
        columnOptions: columnOptions
        )
    .CreateLogger();



builder.Host.UseSerilog();

//Log.Information("Aplikacja uruchomiona");

builder.Services.AddControllersWithViews()
    .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix);

builder.Services.AddLocalization(options => { options.ResourcesPath = "Resources"; });

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
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<TripContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();

// --- WALIDATOR HASŁA DYNAMICZNY ---
builder.Services.AddTransient<IPasswordValidator<ApplicationUser>, DynamicPasswordValidator<ApplicationUser>>();

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
    options.Cookie.SameSite = SameSiteMode.Lax;
});

var app = builder.Build();

// --- LOKALIZACJA ---
app.UseRequestLocalization();

// --- INICJALIZACJA BAZY (SecuritySettings + Role) ---
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<TripContext>();
    context.Database.Migrate();

    // 🔒 Domyślna polityka haseł, jeśli nie istnieje
    if (!context.SecuritySettings.Any())
    {
        context.SecuritySettings.Add(new SecuritySettings
        {
            RequiredLength = 12,
            RequireDigit = false,
            RequireUppercase = false,
            RequireLowercase = false,
            RequireNonAlphanumeric = false,
            PasswordValidity = 30,
            LimitOfWrongPasswords=5,
            BlockTime = TimeSpan.FromMinutes(15),
        });
        context.SaveChanges();
    }

    // 🧩 Role systemowe
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roles = { "ADMIN", "User" };

    foreach (var roleName in roles)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

// --- PIPELINE ---
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

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
