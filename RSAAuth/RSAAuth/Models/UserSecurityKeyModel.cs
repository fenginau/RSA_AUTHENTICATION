using System.ComponentModel.DataAnnotations.Schema;

namespace RSAAuth.Models
{
    public class UserSecurityKeyModel
    {
        public string UserRsaPublicKey { get; set; }
        public string Salt { get; set; }
        public string UserAesKey { get; set; }
    }
}
