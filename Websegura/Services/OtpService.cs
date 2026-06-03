using Supabase;
using Websegura.Models;
using Supabase.Postgrest;
using System;
using System.Threading.Tasks;

namespace Websegura.Services
{
    public class OtpService
    {
        private readonly Supabase.Client _supabase;

        public OtpService(Supabase.Client supabase)
        {
            _supabase = supabase;
        }

        public async Task<string?> GenerateOtp(int userId)
        {
            // Buscamos el usuario en Supabase de forma rápida
            var user = await _supabase.From<User>()
                .Filter("Id", Constants.Operator.Equals, userId)
                .Single();

            if (user == null) return null;

            // Generamos el código aleatorio de 6 dígitos
            var code = new Random().Next(100000, 999999).ToString();
            var expiryTime = DateTime.UtcNow.AddSeconds(120); // 2 minutos exactos en UTC

            // PARCHE: Usamos actualización selectiva para escribir únicamente el OTP sin alterar nada más
            await _supabase.From<User>()
                .Where(x => x.Id == user.Id)
                .Set(x => x.OtpCode, code)
                .Set(x => x.OtpExpiry, expiryTime)
                .Update();

            return code;
        }

        public async Task<bool> ValidateOtp(int userId, string code)
        {
            var user = await _supabase.From<User>()
                .Filter("Id", Constants.Operator.Equals, userId)
                .Single();

            if (user == null) return false;

            // Verificamos si el código coincide
            if (user.OtpCode != code) return false;

            // PARCHE: Forzamos la fecha de la base de datos a convertirse a formato Universal UTC antes de comparar
            if (!user.OtpExpiry.HasValue || user.OtpExpiry.Value.ToUniversalTime() < DateTime.UtcNow)
                return false;

            // PARCHE: Limpiamos los campos de forma selectiva para que el código quede inutilizable tras su uso exitoso
            await _supabase.From<User>()
                .Where(x => x.Id == user.Id)
                .Set(x => x.OtpCode, null)
                .Set(x => x.OtpExpiry, null)
                .Update();

            return true;
        }
    }
}