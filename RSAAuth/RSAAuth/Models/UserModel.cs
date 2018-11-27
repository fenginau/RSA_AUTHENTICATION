using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace RSAAuth.Models
{
    [Table("USER")]
    public class UserModel
    {
        [Key]
        [Column("ID")]
        public Guid Id { get; set; }
        [Column("USERNAME")]
        public string UserName { get; set; }
        [Column("PASSWORD")]
        public string Password { get; set; }
        [Column("LOGIN_ATTEMPTS")]
        public int LoginAttempts { get; set; }
        [Column("TOKEN")]
        public string Token { get; set; }
    }
}
