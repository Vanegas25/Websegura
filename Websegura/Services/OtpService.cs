using OtpNet;
using QRCoder;
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

        // Genera el secret y devuelve el QR en base64 para mostrarlo en la vista
        public async Task<string?> GenerateSetupQr(int userId, string email)
        {
            var secret = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secret);

            // Guardamos el secret en la BD (aún no está habilitado)
            await _supabase.From<User>()
                .Where(x => x.Id == userId)
                .Set(x => x.TotpSecret, base32Secret)
                .Set(x => x.TwoFactorEnabled, false)
                .Update();

            // Generamos el URI para el QR
            var otpUri = $"otpauth://totp/WebSegura:{email}?secret={base32Secret}&issuer=WebSegura";

            // Generamos el QR en base64
            using var qrGenerator = new QRCodeGenerator();
            var qrData = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrData);
            var qrBytes = qrCode.GetGraphic(5);
            return Convert.ToBase64String(qrBytes);
        }

        // Verifica el código ingresado y habilita el 2FA si es correcto
        public async Task<bool> EnableTotp(int userId, string code)
        {
            var user = await _supabase.From<User>()
                .Filter("Id", Constants.Operator.Equals, userId)
                .Single();

            if (user == null || string.IsNullOrEmpty(user.TotpSecret)) return false;

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool valid = totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (valid)
            {
                await _supabase.From<User>()
                    .Where(x => x.Id == user.Id)
                    .Set(x => x.TwoFactorEnabled, true)
                    .Update();
            }

            return valid;
        }

        // Valida el código en cada login
        public async Task<bool> ValidateTotp(int userId, string code)
        {
            var user = await _supabase.From<User>()
                .Filter("Id", Constants.Operator.Equals, userId)
                .Single();

            if (user == null || string.IsNullOrEmpty(user.TotpSecret)) return false;

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            return totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
        }

        public async Task<string?> GetSecret(int userId)
        {
            var user = await _supabase.From<User>()
                .Filter("Id", Constants.Operator.Equals, userId.ToString())
                .Single();
            return user?.TotpSecret;
        }
    }
}