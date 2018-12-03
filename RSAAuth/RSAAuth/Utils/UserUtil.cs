using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NLog;
using RSAAuth.DBContext;
using RSAAuth.Models;

namespace RSAAuth.Utils
{
    public class UserUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        internal static void CreateUser(UserModel user)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    try
                    {
                        user.Salt = Guid.NewGuid().ToString();
                        user.Password = Sha256Encrypt(RsaUtil.Decrypt(user.Password), user.Salt);
                        user.UserName = RsaUtil.Decrypt(user.UserName);
                        context.User.Add(user);
                        RsaUtil.GenerateUserRsaKeyPair(user.Id);
                        context.SaveChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Error(e);
                    }

                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when creating the user.");
            }
        }

        internal static UserSecurityKeyModel ProcessSigninRequest(SigninRequestModel signinRequest)
        {
            try
            {
                var userName = RsaUtil.Decrypt(signinRequest.UserName);
                // get the user id
                var userId = GetUserIdByUserName(userName);
                if (userId == Guid.Empty)
                {
                    throw new KeyNotFoundException("This user does not exist.");
                }

                // save the client RSA public key to database
                RsaUtil.SaveClientKey(signinRequest.ClientRsaPublicKey, userId);
                return GetUserSecurityKey(userId);
            }
            catch (KeyNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to process the sign in request.");
            }
        }

        internal static UserSecurityKeyModel GetUserSecurityKey(Guid userId)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    return new UserSecurityKeyModel
                    {
                        Salt = RsaUtil.Encrypt(context.User.FirstOrDefault(u => u.Id == userId)?.Salt ?? string.Empty, userId, true),
                        UserRsaPublicKey = RsaUtil.GetRsaKeyString(false, userId)
                    };
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to get the user security key.");
            }
        }

        internal static string Signin(SigninRequestModel signinRequest)
        {

            return "";
        }

        private static bool ValidateUser(SigninRequestModel signinRequest)
        {

            return false;
        }

        internal static Guid GetUserIdByUserName(string userName)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    return context.User.FirstOrDefault(u => u.UserName == userName)?.Id ?? Guid.Empty;
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to get the user ID.");
            }
        }

        // Use SHA256 to encrypt the string with salt.
        public static string Sha256Encrypt(string strToHash, string salt)
        {
            var pwdAndSalt = Encoding.UTF8.GetBytes(strToHash + salt);
            var hashBytes = new SHA256Managed().ComputeHash(pwdAndSalt);
            return Convert.ToBase64String(hashBytes);
        }
    }
}
