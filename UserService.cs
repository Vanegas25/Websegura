using System;

using System;
using System.Linq;
using Websegura.Data;
using Websegura.Models;

namespace Websegura.Services
{
    public class UserService
    {
        private readonly AppDbContext _db;

        public UserService(AppDbContext db) => _db = db;

        public bool Register(string username, string email, string password)
        {
            username = username.Trim();
            email = email.Trim();

            if (_db.Users.Any(u => u.Username == username))
                return false;

            var user = new User
            {
                Username = username,
                Email = email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
            };

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

            if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
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

            user.FailedAttempts = 0;
            user.LockedUntil = null;
            _db.SaveChanges();
            return (true, "OK", user);
        }
    }
}