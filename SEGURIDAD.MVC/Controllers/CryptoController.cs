using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SEGURIDAD.MVC.Controllers
{
    public class CryptoController : Controller
    {
        // GET: CryptoController
        public ActionResult Index()
        {
            return View();
        }

        // GET: CryptoController/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: CryptoController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: CryptoController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: CryptoController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: CryptoController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: CryptoController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: CryptoController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
