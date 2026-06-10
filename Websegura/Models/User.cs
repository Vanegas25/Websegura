using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;
using System;

namespace Websegura.Models
{
    [Table("Users")]
    public class User : BaseModel
    {
        [PrimaryKey("Id", false)]
        public long Id { get; set; }

        [Column("Username")]
        public string Username { get; set; }

        [Column("Email")]
        public string Email { get; set; }

        [Column("PasswordHash")]
        public string PasswordHash { get; set; }

        [Column("FailedAttempts")]
        public int FailedAttempts { get; set; }

        [Column("LockedUntil")]
        public DateTime? LockedUntil { get; set; }

        [Column("ResetToken")]
        public string? ResetToken { get; set; }

        [Column("ResetTokenExpiry")]
        public DateTime? ResetTokenExpiry { get; set; }

        [Column("TotpSecret")]
        public string? TotpSecret { get; set; }

        [Column("TwoFactorEnabled")]
        public bool? TwoFactorEnabled { get; set; }
    }
}