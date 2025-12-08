using Microsoft.AspNetCore.Authorization;
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
        [AllowAnonymous]
        public IActionResult Login()
        {
            // 🚫 Si YA está autenticado → NO puede entrar al login → Redirigido a Home
            if (User.Identity != null && User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        // -------------------------------
        // LOGIN (POST)
        // -------------------------------
        [HttpPost]
        [AllowAnonymous]
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
                Secure = true, // <---- OBLIGATORIO EN PRODUCCIÓN
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
            // 🔥 Forma segura de borrar el token
            Response.Cookies.Append("jwt_token", "", new CookieOptions
            {
                Expires = DateTime.UtcNow.AddDays(-1),
                Secure = false,
                HttpOnly = true,
                SameSite = SameSiteMode.Lax
            });

            Response.Cookies.Delete("jwt_token");
            HttpContext.Session.Clear();

            return RedirectToAction("Login");
        }

        // -------------------------------
        // REGISTRO (GET)
        // -------------------------------
        [AllowAnonymous]
        public IActionResult Register()
        {
            // 🚫 No permitir entrar al registro con token activo
            if (User.Identity != null && User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        // -------------------------------
        // REGISTRO (POST)
        // -------------------------------
        [HttpPost]
        [AllowAnonymous]
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

            try
            {
                // Hash de contraseña
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
            catch (ArgumentException ex)
            {
                // Mostrar mensaje de correo inválido en el front
                ViewBag.Error = ex.Message;
                return View(model);
            }
            catch (Exception)
            {
                ViewBag.Error = "Ocurrió un error inesperado. Intente nuevamente.";
                return View(model);
            }
        }
    }
}