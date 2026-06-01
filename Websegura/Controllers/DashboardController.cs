using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using Websegura.Data; // <- CORREGIDO: Cambiado de SecureAccess2FA.Data a Websegura.Data

namespace Websegura.Controllers
{
    public class DashboardController : Controller
    {
        private readonly AppDbContext _db;

        public DashboardController(AppDbContext db) => _db = db;

        private bool IsAuthenticated() =>
            HttpContext.Session.GetInt32("UserId") != null;

        public IActionResult Index()
        {
            if (!IsAuthenticated())
                return RedirectToAction("Login", "Auth");

            var userId = HttpContext.Session.GetInt32("UserId");
            var user = _db.Users.Find(userId);
            ViewBag.Username = user?.Username ?? "Usuario";
            return View();
        }
    }
}