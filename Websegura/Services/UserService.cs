using System;
using System.Linq;
using Microsoft.AspNetCore.Identity; // <- Usamos la seguridad oficial y nativa de .NET
using Websegura.Data;
using Websegura.Models;

namespace Websegura.Services
{
    public class UserService
    {
        private readonly AppDbContext _db;
        // Instanciamos el hash de contraseñas oficial de .NET para el modelo User
        private readonly PasswordHasher<User> _hasher = new PasswordHasher<User>();

        public UserService(AppDbContext db)
        {
            _db = db;
        }

        public bool Register(string username, string email, string password)
        {
            username = username.Trim();
            email = email.Trim();

            if (_db.Users.Any(u => u.Username == username))
                return false;

            var user = new User
            {
                Username = username,
                Email = email
            };

            // Hashea la contraseña de forma nativa y segura
            user.PasswordHash = _hasher.HashPassword(user, password);

            _db.Users.Add(user);
            _db.SaveChanges();
            return true;
        }

        public (bool success, string message, User? user) Login(string username, string password)
        {
            username = username.Trim();

            var user = _db.Users.FirstOrDefault(u => u.Username == username);

            if (user == null)
                return (false, "Usuario no encontrado.", null);

            if (user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
            {
                var mins = (int)(user.LockedUntil.Value - DateTime.UtcNow).TotalMinutes + 1;
                return (false, $"Cuenta bloqueada. Espere {mins} minuto(s).", null);
            }

            // Verifica el hash nativo de .NET
            var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (result == PasswordVerificationResult.Failed)
            {
                user.FailedAttempts++;

                if (user.FailedAttempts >= 3)
                {
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(5);
                    _db.SaveChanges();
                    return (false, "Demasiados intentos. Cuenta bloqueada por 5 minutos.", null);
                }

                _db.SaveChanges();
                return (false, $"Contraseña incorrecta. Intento {user.FailedAttempts}/3.", null);
            }

            // Si entra aquí, la contraseña es correcta. 
            // Reiniciamos intentos y limpiamos bloqueos.
            user.FailedAttempts = 0;
            user.LockedUntil = null;
            _db.SaveChanges();
            return (true, "OK", user);
        }
    }
}