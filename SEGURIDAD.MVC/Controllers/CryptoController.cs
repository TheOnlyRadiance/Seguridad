using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SEGURIDAD.DATA.Interfaces;
using Microsoft.AspNetCore.RateLimiting;

namespace SEGURIDAD.MVC.Controllers
{
    [EnableRateLimiting("IPSafePolicy")]
    public class CryptoController : Controller
    {
        private readonly ICryptoService _encryption;

        public CryptoController(ICryptoService encryption)
        {
            _encryption = encryption;
        }

        
        public IActionResult Cifrar(string texto)
        {
            var cipher = _encryption.EncryptToBase64(texto);
            return Json(new { cifrado = cipher });
        }

        
        public IActionResult Descifrar(string cipher)
        {
            try
            {
                var plain = _encryption.DecryptFromBase64(cipher);
                return Json(new { textoPlano = plain });
            }
            catch (ArgumentException ex)
            {
                return Json(new { textoPlano = (string?)null, error = ex.Message });
            }
            catch (Exception)
            {
                return Json(new { textoPlano = (string?)null, error = "Ocurrió un error inesperado al desencriptar." });
            }
            


        }
        // GET: CryptoController
        public ActionResult Encriptar()
        {
            return View();
        }

        public IActionResult Desencriptar()
        {
            return View();
        } 

        
    }
}
