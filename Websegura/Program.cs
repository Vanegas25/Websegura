using Supabase; // 1. Añade esto
using Websegura.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// 2. ELIMINA EL AddDbContext de SQLite
// builder.Services.AddDbContext<AppDbContext>(options => ...);

// 3. REGISTRA SUPABASE COMO SINGLETON (para usarlo en tus servicios)
var supabaseUrl = builder.Configuration["Supabase:Url"];
var supabaseKey = builder.Configuration["Supabase:Key"];

builder.Services.AddSingleton<Supabase.Client>(provider =>
    new Supabase.Client(supabaseUrl, supabaseKey, new SupabaseOptions
    {
        AutoRefreshToken = true,
        AutoConnectRealtime = true
    }));

// 🔑 Tus servicios (ahora recibirán el cliente Supabase)
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddSingleton<LogService>();
builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddSession(options => { /* ... tus opciones ... */ });

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

// 4. ELIMINA EL BLOQUE "db.Database.EnsureCreated()"
// Ya no necesitas inicializar la base de datos localmente.

app.Run();