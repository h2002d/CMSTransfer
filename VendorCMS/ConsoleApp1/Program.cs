using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Collections;
using System.Security.Cryptography;

namespace ConsoleApp1
{
    class Program
    {

        static void Main(string[] args)
        {
           
            Console.WriteLine(EncryptMessage(Encoding.ASCII.GetBytes("Hello this is a text that is a text and is larger than expected"),""));
            Console.ReadKey();
        }
        public static string EncryptMessage(byte[] text, string key)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.Zeros;
            aes.Mode = CipherMode.CBC;

            aes.Key = Encoding.Default.GetBytes("770A8A65DA156D24EE2A093277530142");
            aes.IV = text;

            string IV = ("-[--IV-[-" + Encoding.Unicode.GetString(aes.IV));

            ICryptoTransform AESEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] buffer = text;

            return
        Convert.ToBase64String(Encoding.Unicode.GetBytes(Encoding.Unicode.GetString(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length)) + IV));

        }
    }
}
