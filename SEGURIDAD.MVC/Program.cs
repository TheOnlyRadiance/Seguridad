using SEGURIDAD.DATA;
using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DATA.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Conexion a la BD
var bdConfig = new BdSQLConfiguration(
    builder.Configuration.GetConnectionString("DefaultConnection")!);

builder.Services.AddSingleton(bdConfig);

//Registrar clave AES64 
var keyBase64 = builder.Configuration["Encryption:Key"];
var key = Convert.FromBase64String(keyBase64);

// Registrar servicio AES-GCM
builder.Services.AddSingleton<ICryptoService>(
    sp => new CriptoRepository(key)
);
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

app.Run();
