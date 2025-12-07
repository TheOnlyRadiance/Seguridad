using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SEGURIDAD.DATA.Interfaces;

namespace SEGURIDAD.MVC.Controllers
{
    public class AuthController : Controller
    {

        private readonly ILoginRepository _loginRepository;

        public AuthController(ILoginRepository loginRepository)
        {
            _loginRepository = loginRepository;
        }

        // Vista Login
        public IActionResult Login()
        {
            return View();
        }

        // Procesar Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string email, string password)
        {
            // Buscar usuario por correo
            var usuario = _loginRepository.Login(email);

            if (usuario == null)
            {
                ViewBag.Error = "El usuario no existe";
                return View();
            }

            // Comparar contraseñas (sin cifrado)
            if (usuario.Contrasena != password)
            {
                ViewBag.Error = "Contraseña incorrecta";
                return View();
            }

            // Guardar sesión
            //HttpContext.Session.SetString("usuario", usuario.Correo);

            return RedirectToAction("Index", "Home");
        }

        // Cerrar sesión
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

    }
}