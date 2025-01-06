using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSATest
{
    class RSA
    {
        public BigInteger PublicKey { get; private set; }  // e
        public BigInteger PrivateKey { get; private set; } // d
        public BigInteger Modulus { get; private set; }    // n

        private int keySize;

        public RSA(int keySize = 1024)
        {
            this.keySize = keySize;
        }
        public string[] getPub_modul()
        {
            string [] dataset = { PublicKey.ToString() , Modulus.ToString() };
            return dataset;
        }
        public void set_keys(BigInteger pubkey, BigInteger privkey, BigInteger modulus)
        {
            PublicKey = pubkey;
            PrivateKey = privkey;
            Modulus = modulus;
        }

        // Генерация пары ключей
        public void GenerateKeys()
        {
            // Генерация двух простых чисел p и q
            BigInteger p = GeneratePrime(keySize / 2);
            BigInteger q = GeneratePrime(keySize / 2);

            // Вычисление n = p * q
            Modulus = p * q;

            // Вычисление phi(n) = (p - 1) * (q - 1)
            BigInteger phi = (p - 1) * (q - 1);

            // Выбор случайной открытой экспоненты e
            do
            {
                PublicKey = RandomInteger(2, phi - 1); // Случайное число в диапазоне [2, phi - 1]
              //  Console.WriteLine($"Trying e: {PublicKey}"); // Отладка
            }
            while (BigInteger.GreatestCommonDivisor(PublicKey, phi) != 1); // Проверка на взаимную простоту

         //   Console.WriteLine($"Final e: {PublicKey}"); // Отладка

            // Вычисление закрытой экспоненты d
            PrivateKey = ModInverse(PublicKey, phi);
        }

        // Шифрование строки
        public string Encrypt(string plainText)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(plainText);
            Array.Reverse(bytes); // Приведение к big-endian
            BigInteger m = new BigInteger(bytes);

            if (m >= Modulus)
                throw new ArgumentException("Сообщение слишком большое для текущего ключа.");

            BigInteger c = BigInteger.ModPow(m, PublicKey, Modulus);
            string test = c.ToString();
            return test;
        }

        // Дешифрование строки
        public string Decrypt(string cipherText)
        {
            BigInteger c = BigInteger.Parse(cipherText);
            BigInteger m = BigInteger.ModPow(c, PrivateKey, Modulus);

            byte[] bytes = m.ToByteArray();
            Array.Reverse(bytes); // Приведение из big-endian
            return Encoding.UTF8.GetString(bytes).TrimEnd('\0'); // Удаление лишних символов
        }

        // Метод для генерации простого числа заданной битности
        private BigInteger GeneratePrime(int bitLength)
        {
            if (bitLength < 2)
                throw new ArgumentException("Длина должна быть не менее 2", nameof(bitLength));

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[bitLength / 8];

            BigInteger candidate;
            do
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] |= 0x01; // Убедимся, что число нечетное
                candidate = new BigInteger(bytes);
            } while (!IsPrime(candidate, 10)); // Проверка на простоту с 10 итерациями

            return candidate;
        }

        // Простая проверка простоты (Тест Миллера-Рабина)
        private bool IsPrime(BigInteger number, int k = 10)
        {
            if (number < 2)
                return false;
            if (number == 2 || number == 3)
                return true;
            if (number % 2 == 0)
                return false;

            // Запись number-1 как 2^s * d
            BigInteger d = number - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            // Выполнение k тестов Миллера-Рабина
            for (int i = 0; i < k; i++)
            {
                BigInteger a = RandomInteger(2, number - 2);
                BigInteger x = BigInteger.ModPow(a, d, number);

                if (x == 1 || x == number - 1)
                    continue;

                bool contOuter = false;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, number);
                    if (x == 1)
                        return false;
                    if (x == number - 1)
                    {
                        contOuter = true;
                        break;
                    }
                }

                if (contOuter)
                    continue;

                return false;
            }

            return true;
        }

        // Генерация случайного BigInteger в диапазоне [min, max]
        private BigInteger RandomInteger(BigInteger min, BigInteger max)
        {
            if (min > max)
                throw new ArgumentException("min должно быть меньше или равно max.");

            BigInteger range = max - min + 1;
            int length = range.ToByteArray().Length; // Получение количества байтов

            byte[] bytes = new byte[length];
            BigInteger result;

            using (var rng = new RNGCryptoServiceProvider())
            {
                do
                {
                    rng.GetBytes(bytes);
                    Array.Reverse(bytes); // Приведение к big-endian
                    result = new BigInteger(bytes);
                }
                while (result < 0 || result >= range); // Убедиться, что результат положительный и в пределах диапазона

                return (result % range) + min; // Используем остаток от деления для того, чтобы результат был в пределах диапазона
            }
        }



        // Вычисление обратного по модулю (Алгоритм расширенного Евклида)
        private BigInteger ModInverse(BigInteger a, BigInteger modulus)
        {
            BigInteger m0 = modulus, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (modulus == 1)
                return 0;

            while (a > 1)
            {
                q = a / modulus;
                t = modulus;

                modulus = a % modulus;
                a = t;
                t = x0;

                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0)
                x1 += m0;

            return x1;
        }
    }
}
