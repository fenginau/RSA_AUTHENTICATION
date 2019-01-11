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
        [Column("NAME")]
        public string Name { get; set; }
        [Column("PASSWORD")]
        public string Password { get; set; }
        [Column("LOGIN_ATTEMPTS")]
        public int LoginAttempts { get; set; }
        [Column("SYM_KEY")]
        public string SymKey { get; set; }
        [Column("SALT")]
        public string Salt { get; set; }
    }
}
