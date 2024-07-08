using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    public static class PrimeGenerator
    {
        /// <summary>
        /// Generates a probable prime number with a specified bit length.
        /// </summary>
        public static BigInteger GeneratePrimeNumber(int bits)
        {
            //byte[] randomNumber = new byte[bits / 8];
            byte[] randomNumber = new byte[(bits + 7) / 8];
            RandomNumberGenerator.Fill(randomNumber);
            /*
            byte[] randomNumber = new byte[(bits + 1) / 8];
            RandomNumberGenerator.Fill(randomNumber);
            randomNumber[randomNumber.Length - 1] |= 0xc0; // Set two highest bits to 1

            
            private BigInteger GenerateRandom(int bits)
            {
                byte[] bytes = new byte[bits / 8];
                _rng.GetBytes(bytes);
                bytes[bytes.Length - 1] |= 0x80; // Ensure the number is positive
                return new BigInteger(bytes);
            }
            */
            BigInteger number = new BigInteger(randomNumber);
            if (number < 0) number = -number;
            number |= 1;// Ensure the number is odd

            while (!IsProbablePrime_MillerRabin(number, 50)) // Matching OpenSSL MR_REPS
            {
                number += 2;
            }

            return number;

            /*
             *  public BigInteger GeneratePrimeNumber(int bits)
    {
        if (bits < 2) throw new ArgumentException("Bit length must be at least 2 bits.", nameof(bits));

        byte[] randomNumber = new byte[(bits + 7) / 8]; // +7 to round up to the nearest byte
        BigInteger number;

        do
        {
            _rng.GetBytes(randomNumber);
            randomNumber[randomNumber.Length - 1] &= 0x7F; // Ensure the number is positive
            randomNumber[randomNumber.Length - 1] |= 0x40; // Set the second highest bit to 1 to ensure the bit length
            randomNumber[0] |= 0x01; // Ensure the number is odd

            number = new BigInteger(randomNumber);
        } while (!IsProbablePrimeMillerRabin(number, 50)); // Matching OpenSSL MR_REPS

        return number;
    }
             */
        }

        public static BigInteger GetCoprime(BigInteger phi)
        {
            BigInteger e;
            do
            {
                // Ensure e is within a suitable range
                var bytes = new byte[phi.ToByteArray().LongLength];
                RandomNumberGenerator.Fill(bytes);

                e = new BigInteger(bytes) % phi; // Ensure e is less than phi
                e = BigInteger.Abs(e); // Ensure e is positive
            } while (BigInteger.GreatestCommonDivisor(e, phi) != 1 || e <= 1);

            return e;
        }

        /// <summary>
        /// Checks if a number is a probable prime using the Miller-Rabin test.
        /// </summary>
        public static bool IsProbablePrime_MillerRabin(BigInteger number, int k)//can take very long time in rsa above 2048
        {
            if (number < 2) return false;
            if (number == 2 || number == 3) return true;
            if (number % 2 == 0) return false;

            BigInteger d = number - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }


            byte[] buffer = new byte[number.GetByteCount()];
            for (int i = 0; i < k; i++)
            {
                BigInteger a;
                do
                {
                    RandomNumberGenerator.Fill(buffer);
                    a = new BigInteger(buffer);
                } while (a < 2 || a >= number - 2);

                BigInteger x = BigInteger.ModPow(a, d, number);
                if (x == 1 || x == number - 1)
                    continue;

                bool composite = true;
                for (int r = 0; r < s - 1; r++)
                {
                    x = BigInteger.ModPow(x, 2, number);
                    if (x == number - 1)
                    {
                        composite = false;
                        break;
                    }
                }

                if (composite)
                    return false;
            }

            return true;
        }

    }
}
