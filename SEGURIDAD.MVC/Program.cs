using SEGURIDAD.DATA;
using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DATA.Repositories;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Conexion a la BD
var bdConfig = new BdSQLConfiguration(
    builder.Configuration.GetConnectionString("DefaultConnection")!);
builder.Services.AddSingleton(bdConfig);

// Registrar clave AES64 
var keyBase64 = builder.Configuration["Encryption:Key"];
var key = Convert.FromBase64String(keyBase64);

// Registrar servicio AES-GCM
builder.Services.AddSingleton<ICryptoService>(
    sp => new CriptoRepository(key)
);

// ------------------------
// PROTECCIÓN DDoS / RATE LIMIT
// ------------------------
builder.Services.AddRateLimiter(options =>
{
    // Limite global (para TODAS las solicitudes)
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.User.Identity?.Name ??
            httpContext.Connection.RemoteIpAddress?.ToString() ??
            "anonymous",
            partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 17, //peticiones que pueda hacer
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));

    // Límite nombrado (para endpoints específicos)
    options.AddFixedWindowLimiter("fixed", opt =>
    {
        opt.PermitLimit = 8; //solicitudes que le da
        opt.Window = TimeSpan.FromSeconds(12); //Cada 12 segundos te da 8 peticiones
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 2;
    });
});

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Limits.MaxRequestBodySize = 1_000_000; // límite 1 MB por request
});

var app = builder.Build();

// Middleware Rate Limiter (antes de Routing)
app.UseRateLimiter();

app.UseRouting();

// Aplicar RateLimiter a controladores (solo al que quieras)
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers().RequireRateLimiting("fixed");
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

app.Run();
