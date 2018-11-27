using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace RSAAuth.Models
{
    [Table("RSA_KEY")]
    internal class RsaRecordModel
    {
        [Key]
        public Guid ID { get; set; }
        [Column("MODULUS")]
        public string Modulus { get; set; }
        [Column("EXPONENT")]
        public string Exponent { get; set; }
        [Column("P")]
        public string P { get; set; }
        [Column("Q")]
        public string Q { get; set; }
        [Column("DP")]
        public string DP { get; set; }
        [Column("DQ")]
        public string DQ { get; set; }
        [Column("INVERSEQ")]
        public string InverseQ { get; set; }
        [Column("D")]
        public string D { get; set; }
        [Column("TYPE")]
        public int Type { get; set; }
        [Column("USER_ID")]
        public Guid User { get; set; }
    }
}