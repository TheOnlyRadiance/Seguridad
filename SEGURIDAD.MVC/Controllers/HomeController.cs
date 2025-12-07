using System.Diagnostics;
using System.Security.Claims;             // <-- importante para obtener el email
using Microsoft.AspNetCore.Authorization; // <-- necesario para [Authorize]
using Microsoft.AspNetCore.Mvc;
using SEGURIDAD.MVC.Models;

namespace SEGURIDAD.MVC.Controllers
{
    [Authorize] // <-- protege todo el controlador con JWT
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            // Obtener email del token JWT
            var correo = User.FindFirst(ClaimTypes.Email)?.Value;

            // Puedes mandar el correo a la vista si quieres
            ViewBag.Correo = correo;

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            });
        }
    }
}
