namespace RSAAuth.Models
{
    public class SigninRequestModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string ClientRsaPublicKey { get; set; }
    }
}
