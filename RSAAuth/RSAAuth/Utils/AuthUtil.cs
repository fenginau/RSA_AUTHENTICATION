using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NLog;
using RSAAuth.Values;

namespace RSAAuth.Utils
{
    public class AuthUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        public static string GenerateToken(Guid userId)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(RsaUtil.GetRsaParameters(true));
            var secretKey = new RsaSecurityKey(rsa);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.NameId, userId.ToString()),
                new Claim(ClaimTypes.Role, "user")
            };
            var token = new JwtSecurityToken(
                issuer: Constant.Issuer,
                audience: Constant.Audience,
                claims: claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(secretKey, SecurityAlgorithms.RsaSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
