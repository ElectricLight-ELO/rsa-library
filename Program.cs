using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSATest
{
    class Program
    {
        static void Main(string[] args)
        {
            RSA rsa = new RSA(512);
            rsa.GenerateKeys();

            string encrypted = rsa.Encrypt("hello world");
            Console.WriteLine("encrypted: " + encrypted);

            string decrypted = rsa.Decrypt(encrypted);
            Console.WriteLine("decrypted: " + decrypted);
            Console.WriteLine("stop");
            Console.ReadKey();
        }
    }
}
