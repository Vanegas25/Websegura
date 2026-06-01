namespace Websegura.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public int FailedAttempts { get; set; } = 0;
        public DateTime? LockedUntil { get; set; }
        public string? OtpCode { get; set; }
        public DateTime? OtpExpiry { get; set; }
    }
}
