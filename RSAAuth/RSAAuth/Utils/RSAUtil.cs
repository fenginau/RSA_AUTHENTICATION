using System;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using NLog;
using RSAAuth.DBContext;
using RSAAuth.Values;
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

                    // write RSA parameters to files as PEM
                    using (var writer = File.CreateText("privatekey.txt"))
                    {
                        ExportPrivateKey(rsa.ExportParameters(true), writer);
                    }
                    using (var writer = File.CreateText("publickey.txt"))
                    {
                        ExportPublicKey(rsa.ExportParameters(false), writer);
                    }

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
                Logger.Error(e);
                throw new Exception("Failed to get the RSA key.");
            }
        }

        internal static string GetRsaKeyString(bool isPrivate, Guid? userId = null, bool isClientPublic = false)
        {
            try
            {
                return isPrivate 
                    ? ExportPrivateKey(GetRsaParameters(true, userId, isClientPublic)) 
                    : ExportPublicKey(GetRsaParameters(false, userId, isClientPublic));
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to get the RSA string key.");
            }
        }

        internal static string Decrypt(string base64Str, Guid? userId = null)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    var rsaParameters = GetRsaParameters(true, userId);
                    rsa.ImportParameters(rsaParameters);
                    var data = Convert.FromBase64String(base64Str);
                    var decryptedData = rsa.Decrypt(data, false);
                    return Encoding.UTF8.GetString(decryptedData);
                }
            }
            catch (CryptographicException e)
            {
                Logger.Error(e);
                return null;
            }
        }

        internal static string Encrypt(string rawStr, Guid? userId = null, bool isClientPublic = false)
        {
            try
            {
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    var rsaParameters = GetRsaParameters(false, userId, isClientPublic);
                    rsa.ImportParameters(rsaParameters);
                    var data = Encoding.UTF8.GetBytes(rawStr);
                    var encryptedData = rsa.Encrypt(data, false);
                    Logger.Info(Convert.ToBase64String(encryptedData));
                    return Convert.ToBase64String(encryptedData);
                }
            }
            catch (CryptographicException e)
            {
                Logger.Error(e);
                return null;
            }
        }

        internal static RSAParameters GetRsaParameters(bool isPrivate, Guid? userId = null, bool isClientPublic = false)
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
                        return parameters;
                    }
                    else
                    {
                        throw new Exception("Cannot Find RSA Record.");
                    }
                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Invalid RSA Record.");
            }
        }

        private static void SaveRsaRecord(RSA rsa, bool isPrivate, Guid? userId = null, bool isClientPublic = false)
        {
            try
            {
                var parameters = rsa.ExportParameters(isPrivate);
                SaveRsaParameters(parameters, isPrivate, userId, isClientPublic);
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Failed to save RSA records.");
            }
        }

        private static void SaveRsaParameters(RSAParameters parameters, bool isPrivate, Guid? userId = null, bool isClientPublic = false)
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
                Logger.Error(e); ;
                throw new Exception("Failed to save RSA parameters.");
            }
        }

        private static string ExportPrivateKey(RSAParameters parameters, TextWriter outputStream = null)
        {
            using (var stream = new MemoryStream())
            {
                var outputString = new StringBuilder();
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeInteger(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeInteger(innerWriter, parameters.Modulus);
                    EncodeInteger(innerWriter, parameters.Exponent);
                    EncodeInteger(innerWriter, parameters.D);
                    EncodeInteger(innerWriter, parameters.P);
                    EncodeInteger(innerWriter, parameters.Q);
                    EncodeInteger(innerWriter, parameters.DP);
                    EncodeInteger(innerWriter, parameters.DQ);
                    EncodeInteger(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);
                outputStream?.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                outputString.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    var subBase64 = base64.Substring(i, Math.Min(64, base64.Length - i));
                    outputString.AppendLine(subBase64);
                    outputStream?.WriteLine(subBase64);
                }
                outputStream?.WriteLine("-----END RSA PRIVATE KEY-----");
                outputString.AppendLine("-----END RSA PRIVATE KEY-----");
                return outputString.ToString();
            }
        }

        private static string ExportPublicKey(RSAParameters parameters, TextWriter outputStream = null)
        {
            using (var stream = new MemoryStream())
            {
                var outputString = new StringBuilder();
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeInteger(paramsWriter, parameters.Modulus); // Modulus
                            EncodeInteger(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);
                outputString.AppendLine("-----BEGIN PUBLIC KEY-----");
                outputStream?.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    var subBase64 = base64.Substring(i, Math.Min(64, base64.Length - i));
                    outputString.AppendLine(subBase64);
                    outputStream?.WriteLine(subBase64);
                }
                outputString.AppendLine("-----END PUBLIC KEY-----");
                outputStream?.WriteLine("-----END PUBLIC KEY-----");
                return outputString.ToString();
            }
        }
        
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeInteger(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            foreach (var v in value)
            {
                if (v != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        internal static void SaveClientKey(string key, Guid userId)
        {
            try
            {
                var rx = new Regex(@"-----.*?-----", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                var keyContent = Regex.Replace(rx.Replace(key, ""), @"\n", "");
                var rsaParams = DecodeX509PublicKey(Convert.FromBase64String(keyContent));
                SaveRsaParameters(rsaParams, false, userId, true);
            }
            catch (Exception e)
            {
                Logger.Info(e);
                throw new Exception("Failed to save the client RSA public key");
            }
        }

        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            var i = 0;
            foreach (var c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        private static RSAParameters DecodeX509PublicKey(byte[] x509Key)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (var mem = new MemoryStream(x509Key))
            {
                using (var br = new BinaryReader(mem))    //wrap Memory Stream with BinaryReader for easy reading
                {
                    try
                    {
                        var twoBytes = br.ReadUInt16();
                        switch (twoBytes)
                        {
                            case 0x8130:
                                br.ReadByte();    //advance 1 byte
                                break;
                            case 0x8230:
                                br.ReadInt16();   //advance 2 bytes
                                break;
                            default:
                                throw new Exception("Failed to convert the PEM key: bytes not correct");
                        }

                        var seq = br.ReadBytes(15);
                        if (!CompareByteArrays(seq, seqOid))  //make sure Sequence for OID is correct
                            throw new Exception("Failed to convert the PEM key: OID sequence is not correct");

                        twoBytes = br.ReadUInt16();
                        if (twoBytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                            br.ReadByte();    //advance 1 byte
                        else if (twoBytes == 0x8203)
                            br.ReadInt16();   //advance 2 bytes
                        else
                            throw new Exception("Failed to convert the PEM key: actual data order");

                        var bt = br.ReadByte();
                        if (bt != 0x00)     //expect null byte next
                            throw new Exception("Failed to convert the PEM key: expect null byte next");

                        twoBytes = br.ReadUInt16();
                        if (twoBytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                            br.ReadByte();    //advance 1 byte
                        else if (twoBytes == 0x8230)
                            br.ReadInt16();   //advance 2 bytes
                        else
                            throw new Exception("Failed to convert the PEM key: actual data order");

                        twoBytes = br.ReadUInt16();
                        byte lowByte = 0x00;
                        byte highByte = 0x00;

                        if (twoBytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                            lowByte = br.ReadByte();  // read next bytes which is bytes in modulus
                        else if (twoBytes == 0x8202)
                        {
                            highByte = br.ReadByte(); //advance 2 bytes
                            lowByte = br.ReadByte();
                        }
                        else
                            throw new Exception("Failed to convert the PEM key: actual data order");
                        byte[] modInt = { lowByte, highByte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                        var modSize = BitConverter.ToInt32(modInt, 0);

                        var firstByte = br.ReadByte();
                        br.BaseStream.Seek(-1, SeekOrigin.Current);

                        if (firstByte == 0x00)
                        {   //if first byte (highest order) of modulus is zero, don't include it
                            br.ReadByte();    //skip this null byte
                            modSize -= 1;   //reduce modulus buffer size by 1
                        }

                        var modulus = br.ReadBytes(modSize); //read the modulus bytes

                        if (br.ReadByte() != 0x02)            //expect an Integer for the exponent data
                            throw new Exception("Failed to convert the PEM key: expect an Integer for the exponent data");
                        var expBytes = br.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                        var exponent = br.ReadBytes(expBytes);

                        // We don't really need to print anything but if we insist to...
                        //showBytes("\nExponent", exponent);
                        //showBytes("\nModulus", modulus);
                        var rsaKeyInfo = new RSAParameters
                        {
                            Modulus = modulus,
                            Exponent = exponent
                        };
                        return rsaKeyInfo;
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Failed to convert the PEM key: " + e.Message);
                    }
                }
            }
        }
    }
}
