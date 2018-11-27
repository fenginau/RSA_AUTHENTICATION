using System;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using NLog;
using RSAAuth.DBContext;
using RSAAuth.Enums;
using RSAAuth.Models;

namespace RSAAuth.Utils
{
    public class RsaUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        internal static void GenerateGlobalRsaKeyPair()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    SaveRsaRecord(rsa, true);
                    SaveRsaRecord(rsa, false);
                }
                catch (Exception e)
                {
                    Logger.Error(e);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        internal static void GenerateUserRsaKeyPair(Guid userId)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    SaveRsaRecord(rsa, true, userId);
                    SaveRsaRecord(rsa, false, userId);
                }
                catch (Exception e)
                {
                    Logger.Error(e);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        internal static RsaRecordModel GetRsaKey(bool isPrivate, Guid? userId = null, bool isClientPublic = false)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    var type = isClientPublic
                        ? RsaRecordType.ClientPublicKey
                        : userId == null
                            ? isPrivate ? RsaRecordType.GlobalPrivateKey : RsaRecordType.GlobalPublicKey
                            : isPrivate ? RsaRecordType.UserPrivateKey : RsaRecordType.UserPublicKey;
                    var record = userId == null
                        ? context.RsaRecord.FirstOrDefault(p => p.Type == type)
                        : context.RsaRecord.FirstOrDefault(p => p.Type == type && p.User == userId);
                    return record;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        internal static string DecryptString(string str)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (var rsa = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo); 
                    var data = Encoding.UTF8.GetBytes(str);
                    decryptedData = rsa.Decrypt(data, false);
                }
                return Encoding.UTF8.GetString(decryptedData);
            }
            catch (CryptographicException e)
            {
                Logger.Error(e);
                return null;
            }
        }

        private static void GetRsaParameters(Guid? userId = null)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    var type = userId == null ? RsaRecordType.GlobalPrivateKey : RsaRecordType.UserPrivateKey;
                    var record = userId == null 
                        ? context.RsaRecord.FirstOrDefault(p => p.Type == type) 
                        : context.RsaRecord.FirstOrDefault(p => p.Type == type && p.User == userId);
                    if (record != null)
                    {
                        var parameters = new RSAParameters
                        {
                            Modulus = record.Modulus != null ? Convert.FromBase64String(record.Modulus) : null,
                            Exponent = record.Exponent != null ? Convert.FromBase64String(record.Exponent) : null,
                            P = record.P != null ? Convert.FromBase64String(record.P) : null,
                            Q = record.Q != null ? Convert.FromBase64String(record.Q) : null,
                            DP = record.DP != null ? Convert.FromBase64String(record.DP) : null,
                            DQ = record.DQ != null ? Convert.FromBase64String(record.DQ) : null,
                            InverseQ = record.InverseQ != null ? Convert.FromBase64String(record.InverseQ) : null,
                            D = record.D != null ? Convert.FromBase64String(record.D) : null
                        };

                    }
                }
            }
            catch
            {
                throw new Exception("Invalid RSA Record.");
            }
        }

        private static void SaveRsaRecord(RSA rsa, bool isPrivate, Guid? userId = null, bool isClientPublic = false)
        {
            try
            {
                var parameters = rsa.ExportParameters(isPrivate);
                using (var context = new AuthContext())
                {
                    var type = isClientPublic 
                        ? RsaRecordType.ClientPublicKey 
                        : userId == null 
                            ? isPrivate ? RsaRecordType.GlobalPrivateKey : RsaRecordType.GlobalPublicKey
                            : isPrivate ? RsaRecordType.UserPrivateKey : RsaRecordType.UserPublicKey;
                    var record = userId == null
                        ? context.RsaRecord.FirstOrDefault(p => p.Type == type)
                        : context.RsaRecord.FirstOrDefault(p => p.Type == type && p.User == userId);
                    if (record != null)
                    {
                        record.Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null;
                        record.Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null;
                        record.P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null;
                        record.Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null;
                        record.DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null;
                        record.DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null;
                        record.InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null;
                        record.D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null;
                        context.RsaRecord.Update(record);
                    }
                    else
                    {
                        var newRecord = new RsaRecordModel
                        {
                            Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                            Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                            P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                            Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                            DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                            DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                            InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                            D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null,
                            Type = type,
                            User = userId ?? Guid.Empty
                        };
                        context.RsaRecord.Add(newRecord);
                    }
                    context.SaveChanges();
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
            }
        }
    }
}
