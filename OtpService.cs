using System;

using Websegura.Data;

namespace Websegura.Services
{
    public class OtpService
    {
        private readonly AppDbContext _db;

        public OtpService(AppDbContext db) => _db = db;

        public string GenerateOtp(int userId)
        {
            var user = _db.Users.Find(userId)!;
            var code = new Random().Next(100000, 999999).ToString();
            user.OtpCode = code;
            user.OtpExpiry = DateTime.UtcNow.AddSeconds(120);
            _db.SaveChanges();
            return code;
        }

        public bool ValidateOtp(int userId, string code)
        {
            var user = _db.Users.Find(userId)!;
            if (user.OtpCode != code) return false;
            if (user.OtpExpiry < DateTime.UtcNow) return false;

            user.OtpCode = null;
            user.OtpExpiry = null;
            _db.SaveChanges();
            return true;
        }
    }
}