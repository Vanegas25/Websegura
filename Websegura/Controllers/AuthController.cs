using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Websegura.Models;
using Websegura.Services;

namespace Websegura.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserService _userService;
        private readonly OtpService _otpService;
        private readonly LogService _log;
        private readonly IEmailSender _emailSender;

        public AuthController(UserService us, OtpService os, LogService ls, IEmailSender es)
        {
            _userService = us;
            _otpService = os;
            _log = ls;
            _emailSender = es;
        }

        // GET: /Auth/Register
        [HttpGet]
        public IActionResult Register() => View();

        // POST: /Auth/Register
        [HttpPost]
        public IActionResult Register(RegisterViewModel model)
        {
            if (model.Password != model.ConfirmPassword)
            {
                ViewBag.Error = "Las contraseñas no coinciden.";
                return View(model);
            }

            bool ok = _userService.Register(model.Username, model.Email, model.Password);
            if (!ok)
            {
                ViewBag.Error = "El usuario ya existe.";
                return View(model);
            }

            _log.Log("REGISTRO", model.Username, "Usuario registrado exitosamente.");
            return RedirectToAction("Login");
        }

        // GET: /Auth/Login
        [HttpGet]
        public IActionResult Login() => View();

        // POST: /Auth/Login
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            // Verificar credenciales de usuario
            var (success, message, user) = _userService.Login(model.Username, model.Password);

            if (!success)
            {
                _log.Log("FALLO_LOGIN", model.Username, message);
                ViewBag.Error = message;
                return View(model);
            }

            // Generar el código OTP en memoria
            var otp = _otpService.GenerateOtp(user!.Id);
            HttpContext.Session.SetInt32("TempUserId", user.Id);

            _log.Log("OTP_GENERADO", model.Username, "Código OTP generado en el servidor.");

            // 📬 ACCIÓN: ENVÍO REAL DEL CORREO ELECTRÓNICO (GMAIL + MAILKIT)
            try
            {
                string asunto = "Código de verificación de 2 pasos - WebSegura";
                string cuerpo = $@"
                    <div style='font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;'>
                        <h2 style='color: #2c3e50; text-align: center;'>Verificación de Dos Pasos</h2>
                        <p>Hola <strong>{user.Username}</strong>,</p>
                        <p>Para completar tu inicio de sesión en WebSegura, utiliza el siguiente código de seguridad:</p>
                        <div style='background-color: #f8f9fa; padding: 15px; text-align: center; border-radius: 4px; margin: 20px 0;'>
                            <h1 style='color: #1a252f; margin: 0; letter-spacing: 4px; font-size: 32px;'>{otp}</h1>
                        </div>
                        <p style='font-size: 12px; color: #7f8c8d;'>Este código es de un solo uso y vencerá pronto. Si no has solicitado este acceso, te sugerimos cambiar tu contraseña de inmediato.</p>
                    </div>";

                // Ejecuta el envío asíncrono hacia el buzón del usuario (user.Email)
                await _emailSender.SendEmailAsync(user.Email, asunto, cuerpo);
            }
            catch (System.Exception ex)
            {
                _log.Log("FALLO_ENVIO_CORREO", model.Username, $"Error al despachar correo: {ex.Message}");
                ViewBag.Error = "Hubo un problema al enviar el código de verificación a tu correo electrónico.";
                return View(model);
            }

            // 💻 ACCIÓN: GUARDAR EN TEMPDATA PARA MOSTRARLO TAMBIÉN EN LA PANTALLA
            TempData["OtpCode"] = otp;
            TempData["OtpUser"] = model.Username;

            return RedirectToAction("Verify2FA");
        }

        // GET: /Auth/Verify2FA
        [HttpGet]
        public IActionResult Verify2FA()
        {
            if (HttpContext.Session.GetInt32("TempUserId") == null)
                return RedirectToAction("Login");
            return View();
        }

        // POST: /Auth/Verify2FA
        [HttpPost]
        public IActionResult Verify2FA(OtpViewModel model)
        {
            var userId = HttpContext.Session.GetInt32("TempUserId");
            if (userId == null) return RedirectToAction("Login");

            // Validar si el código introducido coincide con el generado
            if (_otpService.ValidateOtp(userId.Value, model.Code))
            {
                HttpContext.Session.Remove("TempUserId");
                HttpContext.Session.SetInt32("UserId", userId.Value);
                _log.Log("ACCESO_EXITOSO", userId.ToString()!, "2FA validado correctamente.");
                return RedirectToAction("Index", "Dashboard");
            }

            _log.Log("FALLO_2FA", userId.ToString()!, "Código OTP inválido o expirado.");
            ViewBag.Error = "Código inválido o expirado. Intente de nuevo.";
            return View(model);
        }

        // GET: /Auth/Logout
        public IActionResult Logout()
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            _log.Log("LOGOUT", userId?.ToString() ?? "desconocido", "Sesión cerrada.");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }
    }
}