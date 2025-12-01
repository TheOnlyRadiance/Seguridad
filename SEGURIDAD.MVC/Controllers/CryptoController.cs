using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SEGURIDAD.DATA.Interfaces;

namespace SEGURIDAD.MVC.Controllers
{
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
            var plain = _encryption.DecryptFromBase64(cipher);
            return Json(new { textoPlano = plain });
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
