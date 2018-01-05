using System;
using System.Security.Cryptography;
using System.Text;

namespace Decode
{
    class Program
    {
        
        static void Main(string[] args)
        {
            var input = "Wellcom to viet nam";
            var key = "1234567890123456";
            var Resault = DecodeNew.EncryptString(input, key); 

            Console.WriteLine("Input : {0}", input);
            Console.WriteLine("Key : {0}", key);
            Console.WriteLine("======Reault======");
            Console.WriteLine("Reault Encrypt : {0}", Resault);
            Console.WriteLine("Reault Decrypt : {0}", DecodeNew.DecryptString(Resault, key));
            Console.WriteLine("==================");
        }
    }
}
