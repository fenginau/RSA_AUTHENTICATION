using System;
using System.Collections.Generic;
using System.Data;
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
                    var username = RsaUtil.Decrypt(user.UserName).ToLower();
                    if (context.User.FirstOrDefault(u => u.UserName == username) != null)
                    {
                        throw new DuplicateNameException("Duplicate user");
                    }
                    user.Salt = Guid.NewGuid().ToString();
                    user.Password = Sha256Encrypt(RsaUtil.Decrypt(user.Password), user.Salt);
                    user.UserName = username;
                    user.Name = RsaUtil.Decrypt(user.Name);
                    user.SymKey = AesUtil.GenerateSymmetricKey();
                    context.User.Add(user);
                    RsaUtil.GenerateUserRsaKeyPair(user.Id);
                    context.SaveChanges();
                }
            }
            catch (DuplicateNameException de)
            {
                throw de;
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
                var userName = RsaUtil.Decrypt(signinRequest.UserName).ToLower();
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
                    var user = context.User.FirstOrDefault(u => u.Id == userId);

                    return new UserSecurityKeyModel
                    {
                        Salt = RsaUtil.Encrypt(user?.Salt ?? string.Empty, userId, true),
                        UserAesKey = RsaUtil.Encrypt(user?.SymKey ?? string.Empty, userId, true),
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

        internal static bool CheckUserExist(string username)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    return context.User.FirstOrDefault(u => u.UserName == username) != null;
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when checking the user exist.");
            }
        }

        internal static string Signin(SigninRequestModel signinRequest)
        {
            try
            {
                var userId = GetUserIdByUserName(RsaUtil.Decrypt(signinRequest.UserName).ToLower());
                return ValidateUser(userId, signinRequest.Password) 
                    ? AesUtil.Encrypt(AuthUtil.GenerateToken(userId), userId)
                    : string.Empty;
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to validate the user login.");
            }
        }

        private static bool ValidateUser(Guid userId, string pwdEncrypted)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    var pwdHash = RsaUtil.Decrypt(pwdEncrypted, userId);
                    if (pwdHash == string.Empty)
                    {
                        return false;
                    }
                    var userPwdHash = context.User.FirstOrDefault(u => u.Id == userId)?.Password ?? string.Empty;
                    return pwdHash == userPwdHash;
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to validate the user login.");
            }
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
