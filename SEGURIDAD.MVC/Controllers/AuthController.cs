using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SEGURIDAD.DATA.Interfaces;
using SEGURIDAD.DTOS.Auth;

namespace SEGURIDAD.MVC.Controllers
{
    public class AuthController : Controller
    {
        private readonly ILoginRepository _loginRepository;
        private readonly ITokenRepository _tokenService;

        public AuthController(ILoginRepository loginRepository, ITokenRepository tokenService)
        {
            _loginRepository = loginRepository;
            _tokenService = tokenService;
        }

        // -------------------------------
        // LOGIN (GET)
        // -------------------------------
        public IActionResult Login()
        {
            return View();
        }

        // -------------------------------
        // LOGIN (POST)
        // -------------------------------
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string email, string password)
        {
            var usuario = _loginRepository.Login(email);

            if (usuario == null)
            {
                ViewBag.Error = "El usuario no existe";
                return View("Login");
            }

            if (!BCrypt.Net.BCrypt.Verify(password, usuario.Contrasena))
            {
                ViewBag.Error = "Contraseña incorrecta";
                return View("Login");
            }

            // GENERAR JWT
            var token = _tokenService.GenerateToken(usuario.Correo, usuario.IdUsuario);

            Response.Cookies.Append("jwt_token", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddHours(1)
            });

            return RedirectToAction("Index", "Home");
        }

        // -------------------------------
        // LOGOUT
        // -------------------------------
        public IActionResult Logout()
        {
            Response.Cookies.Delete("jwt_token");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        // -------------------------------
        // REGISTRO (GET)
        // -------------------------------
        public IActionResult Register()
        {
            return View();
        }

        // -------------------------------
        // REGISTRO (POST)
        // -------------------------------
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(RegistroDTO model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var existe = _loginRepository.Login(model.Correo);

            if (existe != null)
            {
                ViewBag.Error = "El correo ya está registrado.";
                return View(model);
            }

            // HASH DE CONTRASEÑA
            var hash = BCrypt.Net.BCrypt.HashPassword(model.Contrasena);

            var ok = _loginRepository.RegistrarUsuario(model.Correo, hash);

            if (!ok)
            {
                ViewBag.Error = "No se pudo registrar el usuario.";
                return View(model);
            }

            TempData["mensaje"] = "Usuario registrado correctamente. Ahora inicia sesión.";
            return RedirectToAction("Login");
        }
    }
}
