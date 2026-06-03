using Microsoft.AspNetCore.Identity;
using Supabase;
using Websegura.Models;
using static Supabase.Postgrest.Constants;
using System;
using System.Threading.Tasks;

namespace Websegura.Services
{
    public class UserService
    {
        private readonly Supabase.Client _supabase;
        private readonly PasswordHasher<User> _hasher = new PasswordHasher<User>();

        public UserService(Supabase.Client supabase)
        {
            _supabase = supabase;
        }

        public async Task<bool> Register(string username, string email, string password)
        {
            username = username.Trim();
            email = email.Trim().ToLower();

            var existing = await _supabase.From<User>()
                .Filter("Username", Operator.Equals, username)
                .Single();

            if (existing != null) return false;

            var user = new User
            {
                Username = username,
                Email = email
            };

            user.PasswordHash = _hasher.HashPassword(user, password);

            await _supabase.From<User>().Insert(user);
            return true;
        }

        public async Task<(bool success, string message, User? user)> Login(string username, string password)
        {
            username = username.Trim();

            var user = await _supabase.From<User>()
               .Filter("Username", Operator.Equals, username)
                .Single();

            if (user == null)
                return (false, "Usuario no encontrado.", null);

            if (user.LockedUntil.HasValue && user.LockedUntil.Value.ToUniversalTime() > DateTime.UtcNow)
            {
                var mins = (int)(user.LockedUntil.Value.ToUniversalTime() - DateTime.UtcNow).TotalMinutes + 1;
                return (false, $"Cuenta bloqueada. Espere {mins} minuto(s).", null);
            }

            var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (result == PasswordVerificationResult.Failed)
            {
                int nuevosIntentos = user.FailedAttempts + 1;
                DateTime? nuevoBloqueo = null;

                if (nuevosIntentos >= 3)
                {
                    nuevoBloqueo = DateTime.UtcNow.AddMinutes(5);
                }

                // Actualización selectiva para no tocar ni limpiar columnas de tokens de recuperación u OTPs
                await _supabase.From<User>()
                    .Where(x => x.Id == user.Id)
                    .Set(x => x.FailedAttempts, nuevosIntentos)
                    .Set(x => x.LockedUntil, nuevoBloqueo)
                    .Update();

                return (false, nuevosIntentos >= 3 ? "Cuenta bloqueada." : "Contraseña incorrecta.", null);
            }

            // Actualización selectiva al entrar con éxito para dejar intacto el ResetToken u OtpCode si existen
            await _supabase.From<User>()
                .Where(x => x.Id == user.Id)
                .Set(x => x.FailedAttempts, 0)
                .Set(x => x.LockedUntil, null)
                .Update();

            return (true, "OK", user);
        }

        // ==========================================
        // RECUPERACIÓN DE CONTRASEÑA
        // ==========================================

        public async Task<(bool userExists, string token)> GeneratePasswordResetToken(string email)
        {
            if (string.IsNullOrEmpty(email)) return (false, "");
            email = email.Trim().ToLower();

            var user = await _supabase.From<User>()
                .Filter("Email", Operator.Equals, email)
                .Single();

            if (user == null) return (false, "");

            string token = Guid.NewGuid().ToString();

            await _supabase.From<User>()
                .Where(x => x.Id == user.Id)
                .Set(x => x.ResetToken, token)
                .Set(x => x.ResetTokenExpiry, DateTime.UtcNow.AddMinutes(20))
                .Update();

            return (true, token);
        }

        public async Task<bool> ResetPassword(string email, string token, string newPassword)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token)) return false;
            email = email.Trim().ToLower();

            var user = await _supabase.From<User>()
                .Filter("Email", Operator.Equals, email)
                .Single();

            if (user == null) return false;
            if (user.ResetToken != token) return false;

            // Comparación limpia en formato UTC
            if (!user.ResetTokenExpiry.HasValue || user.ResetTokenExpiry.Value.ToUniversalTime() < DateTime.UtcNow)
                return false;

            string newPasswordHash = _hasher.HashPassword(user, newPassword);

            await _supabase.From<User>()
                .Where(x => x.Id == user.Id)
                .Set(x => x.PasswordHash, newPasswordHash)
                .Set(x => x.ResetToken, null)
                .Set(x => x.ResetTokenExpiry, null)
                .Update();

            return true;
        }
    }
}