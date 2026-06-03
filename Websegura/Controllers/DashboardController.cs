using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Supabase;
using Websegura.Models;
using Supabase.Postgrest; // <--- AGREGA ESTO. Es vital para reconocer Constants.Operator

namespace Websegura.Controllers
{
    public class DashboardController : Controller
    {
        private readonly Supabase.Client _supabase;

        public DashboardController(Supabase.Client supabase) => _supabase = supabase;

        private bool IsAuthenticated() =>
            HttpContext.Session.GetInt32("UserId") != null;

        public async Task<IActionResult> Index() // Cambiado a async Task
        {
            if (!IsAuthenticated())
                return RedirectToAction("Login", "Auth");

            var userId = HttpContext.Session.GetInt32("UserId") ?? 0;

            // Buscamos el usuario en Supabase de forma asíncrona
            var response = await _supabase.From<User>()
             .Filter("Id", Constants.Operator.Equals, userId) // Cambia Postgrest.Constants por solo Constants
             .Single();

            var user = response;
            ViewBag.Username = user?.Username ?? "Usuario";

            return View();
        }
    }
}