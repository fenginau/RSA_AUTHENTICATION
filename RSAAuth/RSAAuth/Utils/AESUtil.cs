using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NLog;
using RSAAuth.DBContext;
using RSAAuth.Models;

namespace RSAAuth.Utils
{
    public class AesUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        internal static string GenerateSymmetricKey()
        {
            try
            {
                using (var aes = Aes.Create())
                {
                    var key = aes.Key;
                    var iv = aes.IV;
                    return $"{Convert.ToBase64String(key)}:{Convert.ToBase64String(iv)}";
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when generate the user symmetric key.");
            }
        }

        internal static AesKeyPairModel GetAesKeyPair(Guid userId)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    var keyPairStr = context.User.Where(u => u.Id == userId).Select(p => p.SymKey).FirstOrDefault() ??
                                     string.Empty;
                    var pair = keyPairStr.Split(":");
                    return new AesKeyPairModel
                    {
                        Key = pair[0],
                        Iv = pair[1]
                    };
                }
            }
            catch (IndexOutOfRangeException ie)
            {
                Logger.Error(ie);
                throw new Exception($"The symmetric key pair for user {userId} is not correct.");
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when retrieving the user symmetric key.");
            }
        }

        internal static string Encrypt(string plainText, Guid userId)
        {
            try
            {
                var pair = GetAesKeyPair(userId);

                using (var aes = Aes.Create())
                {
                    aes.Key = Convert.FromBase64String(pair.Key);
                    aes.IV = Convert.FromBase64String(pair.Iv);
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText);
                            }
                            return Convert.ToBase64String(msEncrypt.ToArray());
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when encrypting using AES.");
            }
        }

        internal static string Decrypt(string cipherText, Guid userId)
        {
            try
            {
                var pair = GetAesKeyPair(userId);

                using (var aes = Aes.Create())
                {
                    aes.Key = Convert.FromBase64String(pair.Key);
                    aes.IV = Convert.FromBase64String(pair.Iv);
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when decrypting using AES.");
            }
        }
    }
}
