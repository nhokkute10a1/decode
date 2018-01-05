using System;
using System.Text;
using System.Security.Cryptography;
namespace Decode
{
    public static class Decode
    {
        public static RijndaelManaged GetRijndaelManaged(String secretKey)
        {
            var keyBytes = new byte[16];
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            Array.Copy(secretKeyBytes, keyBytes, Math.Min(keyBytes.Length, secretKeyBytes.Length));
            return new RijndaelManaged
            {
                /*
                    CBC : Khi mã hóa mỗi block thì ngoài việc sử dụng KEY ra thì nó còn sử dụng kết quả của Block trước đó làm tham số. Cứ như thế, khi hỏng 1 block có thể ảnh hưởng đến rất nhiều block khác nữa.
                    ECB : Các block được mã hóa riêng rẽ, một block bị hỏng hoàn toàn không ảnh hưởng đến việc giải mã các block khác
                 */
                Mode = CipherMode.CBC,
                //Padding = PaddingMode.PKCS7,
                /*
                    Độ dài của Byte
                 */
                Padding = PaddingMode.PKCS7,
                /*
                    Kiểu mã hoá có thể là 128,256,512
                 */
                KeySize = 128,
                BlockSize = 128,
                Key = keyBytes,
                IV = keyBytes
            };
        }
        public static byte[] Encrypt(byte[] plainBytes, RijndaelManaged rijndaelManaged)
        {


            return rijndaelManaged.CreateEncryptor()
                .TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }
        public static byte[] Decrypt(byte[] encryptedData, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateDecryptor()
                .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }
        /*==Sử dụng 2 hàm dưới để mã hoá và giải mã==*/
        public static String Encrypt(String plainText, String key)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(Encrypt(plainBytes, GetRijndaelManaged(key)));
        }
        public static String Decrypt(String encryptedText, String key)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedText);
            return Encoding.UTF8.GetString(Decrypt(encryptedBytes, GetRijndaelManaged(key)));
        }
    }
}
