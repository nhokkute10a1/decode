using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Decode
{
    public static class DecodeNew
    {
        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            /*
                Thứ 1 hỏi là mãng byte là 8 byte hay 16 byte
                Thứ 2 hỏi là KeySize là 256 hay 128
             */
            byte[] saltBytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            //var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var ms = new MemoryStream())
            {
                using (var AES = new RijndaelManaged())
                {
                    AES.KeySize = 128;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Mode = CipherMode.CBC;
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            //byte[] saltBytes = { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (var ms = new MemoryStream())
            {
                using (var AES = new RijndaelManaged())
                {
                    AES.KeySize = 128;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;
                    AES.Padding = PaddingMode.PKCS7;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
        public static string EncryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            return result;
        }
        public static string DecryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            string result = Encoding.UTF8.GetString(bytesDecrypted);

            return result;
        }
        public static string EncryptString(string text, string password)
        {
            var baPwd = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            var baPwdHash = SHA256.Create().ComputeHash(baPwd);

            var baText = Encoding.UTF8.GetBytes(text);

            var baSalt = GetRandomBytes();
            var baEncrypted = new byte[baSalt.Length + baText.Length];

            // Combine Salt + Text
            for (var i = 0; i < baSalt.Length; i++)
                baEncrypted[i] = baSalt[i];
            for (var i = 0; i < baText.Length; i++)
                baEncrypted[i + baSalt.Length] = baText[i];

            baEncrypted = AES_Encrypt(baEncrypted, baPwdHash);

            var result = Convert.ToBase64String(baEncrypted);
            return result;
        }
        public static string DecryptString(string text, string password)
        {
            var baPwd = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            var baPwdHash = SHA256.Create().ComputeHash(baPwd);

            var baText = Convert.FromBase64String(text);

            var baDecrypted = AES_Decrypt(baText, baPwdHash);

            // Remove salt
            var saltLength = GetSaltLength();
            var baResult = new byte[baDecrypted.Length - saltLength];
            for (var i = 0; i < baResult.Length; i++)
                baResult[i] = baDecrypted[i + saltLength];

            var result = Encoding.UTF8.GetString(baResult);
            return result;
        }
        public static byte[] GetRandomBytes()
        {
            var saltLength = GetSaltLength();
            var ba = new byte[saltLength];
            RandomNumberGenerator.Create().GetBytes(ba);
            return ba;
        }
        public static int GetSaltLength()
        {
            return 8;
        }
    }
}
