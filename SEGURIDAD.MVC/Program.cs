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
//  CONFIG PORT FOR RAILWAY
// -------------------------------------------------------------
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(int.Parse(port));
});

// -------------------------------------------------------------
// MVC
// -------------------------------------------------------------
builder.Services.AddControllersWithViews();

// Sessions
builder.Services.AddSession();

// -------------------------------------------------------------
// BASE DE DATOS
// -------------------------------------------------------------
var connectionString = Environment.GetEnvironmentVariable("DEFAULT_CONNECTION")
                       ?? builder.Configuration.GetConnectionString("DefaultConnection");

var bdConfig = new BdSQLConfiguration(connectionString!);
builder.Services.AddSingleton(bdConfig);

// Repositorios
builder.Services.AddScoped<ILoginRepository, LoginRepository>();
builder.Services.AddSingleton<ITokenRepository, TokenRepository>();

// -------------------------------------------------------------
// 🔐 AES-GCM — clave Base64 desde variable de entorno o appsettings.json
// -------------------------------------------------------------
var keyBase64 = Environment.GetEnvironmentVariable("ENCRYPTION_KEY")
                 ?? builder.Configuration["Encryption:Key"];

if (string.IsNullOrEmpty(keyBase64))
    throw new Exception("❌ ERROR: Falta Encryption:Key");

var keyBytes = Convert.FromBase64String(keyBase64);

// Registrar ICryptoService
builder.Services.AddSingleton<ICryptoService>(sp =>
    new CriptoRepository(keyBytes)
);

// -------------------------------------------------------------
// 🔥 JWT CONFIG
// -------------------------------------------------------------
var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
               ?? builder.Configuration["Jwt:Key"];

var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER")
                ?? builder.Configuration["Jwt:Issuer"];

var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE")
                  ?? builder.Configuration["Jwt:Audience"];

if (string.IsNullOrEmpty(jwtKey))
    throw new Exception("❌ ERROR: Falta Jwt:Key");

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
        ValidIssuer = jwtIssuer,

        ValidateAudience = true,
        ValidAudience = jwtAudience,

        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero // <--- obligatorio
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
// ORDEN DE MIDDLEWARES
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

app.Use(async (context, next) =>
{
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    context.Response.Headers["Pragma"] = "no-cache";
    context.Response.Headers["Expires"] = "0";
    await next();
});

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
