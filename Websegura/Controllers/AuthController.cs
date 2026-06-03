using System;
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

        // ==========================================
        // REGISTRO DE USUARIOS
        // ==========================================
        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (model.Password != model.ConfirmPassword)
            {
                ViewBag.Error = "Las contraseñas no coinciden.";
                return View(model);
            }

            bool ok = await _userService.Register(model.Username, model.Email, model.Password);
            if (!ok)
            {
                ViewBag.Error = "El usuario ya existe.";
                return View(model);
            }

            _log.Log("REGISTRO", model.Username, "Usuario registrado exitosamente.");
            return RedirectToAction("Login");
        }

        // ==========================================
        // INICIO DE SESIÓN (LOGIN) CON BLOQUEO
        // ==========================================
        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            string sessionKeyIntentos = $"Intentos_{model.Username}";
            string sessionKeyBloqueo = $"Bloqueo_{model.Username}";

            // 1. Comprobar si el usuario está bloqueado temporalmente
            string bloqueoStr = HttpContext.Session.GetString(sessionKeyBloqueo);
            if (!string.IsNullOrEmpty(bloqueoStr))
            {
                DateTime tiempoBloqueo = DateTime.Parse(bloqueoStr);

                if (DateTime.Now < tiempoBloqueo)
                {
                    TimeSpan restantes = tiempoBloqueo - DateTime.Now;
                    string msgBloqueo = $"Tu acceso está bloqueado temporalmente por exceso de intentos. Inténtalo de nuevo en {restantes.Minutes}m y {restantes.Seconds}s.";

                    _log.Log("INTENTO_BLOQUEADO", model.Username, "El usuario intentó ingresar estando suspendido.");
                    ViewBag.Error = msgBloqueo;
                    return View(model);
                }
                else
                {
                    HttpContext.Session.Remove(sessionKeyBloqueo);
                    HttpContext.Session.Remove(sessionKeyIntentos);
                }
            }

            // 2. Intento de inicio de sesión real
            var (success, message, user) = await _userService.Login(model.Username, model.Password);

            if (!success)
            {
                _log.Log("FALLO_LOGIN", model.Username, message);

                int intentos = HttpContext.Session.GetInt32(sessionKeyIntentos) ?? 0;
                intentos++;
                HttpContext.Session.SetInt32(sessionKeyIntentos, intentos);

                if (intentos >= 3)
                {
                    DateTime horaDesbloqueo = DateTime.Now.AddMinutes(5);
                    HttpContext.Session.SetString(sessionKeyBloqueo, horaDesbloqueo.ToString());
                    ViewBag.Error = "Has alcanzado el máximo de intentos permitidos (3/3). Tu acceso ha sido bloqueado por 5 minutos.";
                }
                else
                {
                    ViewBag.Error = $"{message} Intento {intentos}/3.";
                }

                return View(model);
            }

            // 3. Login correcto: Limpiar historial de intentos del usuario
            HttpContext.Session.Remove(sessionKeyIntentos);
            HttpContext.Session.Remove(sessionKeyBloqueo);

            // 4. FLUJO SEGURO DE OTP: Primero fijamos la sesión, luego creamos el OTP asíncrono
            HttpContext.Session.SetInt32("TempUserId", (int)user!.Id);
            var otp = await _otpService.GenerateOtp((int)user.Id);

            _log.Log("OTP_GENERADO", model.Username, "Código OTP generado en el servidor.");

            try
            {
                string asunto = "Código de verificación de 2 pasos - WebSegura";
                string cuerpo = $"<p>Tu código de seguridad es: <strong>{otp}</strong></p>";
                await _emailSender.SendEmailAsync(user.Email, asunto, cuerpo);
            }
            catch (System.Exception ex)
            {
                _log.Log("FALLO_ENVIO_CORREO", model.Username, $"Error: {ex.Message}");
                ViewBag.Error = "Hubo un problema al enviar el código.";
                return View(model);
            }

            TempData["OtpCode"] = otp;
            TempData["OtpUser"] = model.Username;

            return RedirectToAction("Verify2FA");
        }

        // ==========================================
        // VERIFICACIÓN DE DOS FACTORES (2FA)
        // ==========================================
        [HttpGet]
        public IActionResult Verify2FA()
        {
            if (HttpContext.Session.GetInt32("TempUserId") == null)
                return RedirectToAction("Login");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Verify2FA(OtpViewModel model)
        {
            var userId = HttpContext.Session.GetInt32("TempUserId");
            if (userId == null) return RedirectToAction("Login");

            if (await _otpService.ValidateOtp(userId.Value, model.Code))
            {
                HttpContext.Session.Remove("TempUserId");
                HttpContext.Session.SetInt32("UserId", userId.Value);
                _log.Log("ACCESO_EXITOSO", userId.ToString()!, "2FA validado correctamente.");
                return RedirectToAction("Index", "Dashboard");
            }

            _log.Log("FALLO_2FA", userId.ToString()!, "Código OTP inválido o expirado.");
            ViewBag.Error = "Código inválido o expirado.";
            return View(model);
        }

        // ==========================================
        // RECUPERACIÓN DE CONTRASEÑA: SOLICITUD
        // ==========================================
        [HttpGet]
        public IActionResult ForgotPassword() => View();

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var (userExists, token) = await _userService.GeneratePasswordResetToken(model.Email);

            if (userExists && !string.IsNullOrEmpty(token))
            {
                try
                {
                    var callbackUrl = Url.Action("ResetPassword", "Auth",
                        new { token = token, email = model.Email },
                        protocol: Request.Scheme);

                    string asunto = "Restablecer Contraseña - WebSegura";
                    string cuerpo = $@"
                        <h3>Solicitud de restablecimiento de contraseña</h3>
                        <p>Para cambiar tu contraseña, haz clic en el siguiente enlace (expira en 20 minutos):</p>
                        <p><a href='{callbackUrl}' style='padding:10px 20px; background-color:#ff477e; color:white; text-decoration:none; border-radius:5px;'>Restablecer Contraseña</a></p>
                        <p>Si no solicitaste este cambio, puedes ignorar este correo.</p>";

                    await _emailSender.SendEmailAsync(model.Email, asunto, cuerpo);
                    _log.Log("SOLICITUD_RESET_PASS", model.Email, "Correo de recuperación enviado exitosamente.");
                }
                catch (System.Exception ex)
                {
                    _log.Log("FALLO_ENVIO_RESET", model.Email, $"Error: {ex.Message}");
                    ViewBag.Error = "Hubo un problema al enviar el correo de recuperación.";
                    return View(model);
                }
            }

            ViewBag.Success = "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña en unos minutos.";
            return View();
        }

        // ==========================================
        // RECUPERACIÓN DE CONTRASEÑA: CAMBIO REAL
        // ==========================================
        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Login");
            }

            // Parche definitivo: Decodificamos strings para evitar roturas por caracteres especiales de navegadores
            var cleanToken = Uri.UnescapeDataString(token);
            var cleanEmail = Uri.UnescapeDataString(email);

            var model = new ResetPasswordViewModel { Token = cleanToken, Email = cleanEmail };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (model.Password != model.ConfirmPassword)
            {
                ViewBag.Error = "Las contraseñas no coinciden.";
                return View(model);
            }

            bool resetExitoso = await _userService.ResetPassword(model.Email, model.Token, model.Password);

            if (!resetExitoso)
            {
                ViewBag.Error = "El enlace es inválido, ha expirado o ya fue utilizado.";
                return View(model);
            }

            _log.Log("RESET_PASS_EXITOSO", model.Email, "Contraseña restablecida correctamente.");

            TempData["SuccessMessage"] = "Tu contraseña ha sido restablecida con éxito. Ya puedes iniciar sesión.";
            return RedirectToAction("Login");
        }

        // ==========================================
        // CIERRE DE SESIÓN (LOGOUT)
        // ==========================================
        public IActionResult Logout()
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            _log.Log("LOGOUT", userId?.ToString() ?? "desconocido", "Sesión cerrada.");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }
    }
}