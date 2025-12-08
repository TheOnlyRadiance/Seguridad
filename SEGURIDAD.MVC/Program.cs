using SEGURIDAD.DATA;
using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DATA.Repositories;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------
// MVC
// -------------------------------------------------------------
builder.Services.AddControllersWithViews();

// Sessions
builder.Services.AddSession();

// -------------------------------------------------------------
// BASE DE DATOS
// -------------------------------------------------------------
var bdConfig = new BdSQLConfiguration(builder.Configuration.GetConnectionString("DefaultConnection")!);
builder.Services.AddSingleton(bdConfig);

// Repositorios
builder.Services.AddScoped<ILoginRepository, LoginRepository>();
builder.Services.AddSingleton<ITokenRepository, TokenRepository>();

// -------------------------------------------------------------
// 🔐 AES-GCM — clave Base64 desde appsettings.json
// -------------------------------------------------------------
var keyBase64 = builder.Configuration["Encryption:Key"];
if (string.IsNullOrEmpty(keyBase64))
    throw new Exception("❌ ERROR: Falta Encryption:Key en appsettings.json");

var keyBytes = Convert.FromBase64String(keyBase64);

// Registrar ICryptoService (MUY IMPORTANTE)
builder.Services.AddSingleton<ICryptoService>(sp =>
    new CriptoRepository(keyBytes)
);

// -------------------------------------------------------------
// 🔥 JWT CONFIG
// -------------------------------------------------------------
var jwtKey = builder.Configuration["Jwt:Key"];
if (string.IsNullOrEmpty(jwtKey))
    throw new Exception("❌ ERROR: Falta Jwt:Key en appsettings.json");

var jwtKeyBytes = Convert.FromBase64String(jwtKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),

        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],

        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],

        ValidateLifetime = true,

        // 🔥 evita errores raros con la fecha del token
        ClockSkew = TimeSpan.Zero
    };

    // 🔥 JWT desde cookie
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var token = context.Request.Cookies["jwt_token"];

            if (!string.IsNullOrEmpty(token))
                context.Token = token;

            return Task.CompletedTask;
        }
    };
});

// -------------------------------------------------------------
// 🛡 RATE LIMIT (DDoS protection)
// -------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        // Mensaje de error personalizado
        await context.HttpContext.Response.WriteAsync(
            "Has superado el límite de peticiones. Por favor espera unos segundos e intenta nuevamente.");
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetTokenBucketLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "anon",
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = 100, //peticiones por usuario
                TokensPerPeriod = 20, //Recarga cada periodo
                ReplenishmentPeriod = TimeSpan.FromSeconds(15), //Cada 15 Segundos
                AutoReplenishment = true,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }
        )
    );
});



var app = builder.Build();

// -------------------------------------------------------------
// ORDEN DE MIDDLEWARES (IMPORTANTE)
// -------------------------------------------------------------
app.UseRateLimiter();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// SESSION va ANTES del auth
app.UseSession();

// 🔐 autenticación JWT
app.UseAuthentication();
app.UseAuthorization();

// -------------------------------------------------------------
// RUTEO MVC
// -------------------------------------------------------------
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

app.Run();
