using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using NLog;

namespace RSAAuth.Utils
{
    public class AuthUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private const string SecretKey = "1234567890111213141516";
        public static string GenerateToken(string username)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.NameId, username),
                new Claim(ClaimTypes.Role, "user")
            };
            var token = new JwtSecurityToken(
                issuer: "feng",
                audience: "feng-client",
                claims: claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256)
            );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }

        public static bool IsValidLogin(string un, string pw)
        {
            var username = "test";
            var password = "password";
            //var salt = Guid.NewGuid().ToString();
            var salt = "6782DFB0-40AB-4F86-B703-15A9176B99F5";

            //SHA256 encryption
            //client side
            var hash1 = GetHashString(password, username);
            var pwHash = GetHashString(pw, salt);

            //server side
            var hash2 = GetHashString(hash1, salt);
            Logger.Info("hash1: " + hash1);
            Logger.Info("hashp: " + pwHash);
            Logger.Info("hash2: " + hash2);
            if (un == username && pwHash == hash2)
            {
                return true;
            }

            return false;
        }

        public static string GetHashString(string strToHash, string salt)
        {
            byte[] pwdAndSalt = Encoding.UTF8.GetBytes(strToHash + salt);
            byte[] hashBytes = new SHA256Managed().ComputeHash(pwdAndSalt);
            return Convert.ToBase64String(hashBytes);
        }
    }
}
