using Microsoft.EntityFrameworkCore;
using Websegura.Data;
using Websegura.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// 🔄 Configuración para SQLite
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=websegura.db"));

// 🔑 Inyección de tus servicios del sistema
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddSingleton<LogService>();

// ✉️ REGISTRO DEL SERVICIO DE CORREO (Añadido aquí)
builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // Si el archivo .db no existe, lo creará automáticamente al arrancar
    db.Database.EnsureCreated();
}

app.Run();