using System;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace RSA
{
    public partial class ManagedRSA : IDisposable
    {
        private readonly int _keySize;
        //
        private readonly bool _genPublicKey = false;//should be false, true for testing/education only
        private readonly bool _usePadding = true;//must fo safety
        private readonly bool _useOaep = false;//oaep-mgf1 is safer ,works in 2048, pkcs for old compatibility not safe
        //
        private readonly bool _useBlinding = false;//against side-channel attacks , doesn't work yet
        private readonly bool _useMontgomery = false;//doesn't work yet
        //
        private readonly bool _useCrtDecrypt = true;//recommended for perf
        //
        private BigInteger _privateKey;//_d _privateExponent
        private BigInteger _publicKey = 0x10001;//_e _publicExponent coprime //0x10001=65537
        private BigInteger _modulus;//_n
        //
        private BigInteger _p;//prime factor 1
        private BigInteger _q;//prime factor 2

        //fields of modern impl, crt:

        private BigInteger _dp;//private exponent mod (p-1). , Chinese Remainder Theorem (CRT).
        private BigInteger _dq;//private exponent mod (q-1). , Chinese Remainder Theorem (CRT).
        private BigInteger _qInv;//InverseQ, inverse of q mod p. , Chinese Remainder Theorem (CRT).

        //not needed to be saved to file(r ,rInv):
        private BigInteger _r;//R for Montgomery multiplication
        private BigInteger _rInv;//R inverse for Montgomery multiplication
        private BigInteger _nInv;//negative R inverse for Montgomery multiplication
        //
        private bool _isPublicKeyLoaded = false;
        private bool _isPrivateKeyLoaded = false;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the ManagedRSA class with a specified key size.
        /// </summary>
        public ManagedRSA(int keySize = 2048)//3072-8192 recommended but prime generation takes too long
        {
            if (keySize < 2048)
                throw new ArgumentException("Key size must be at least 2048 bits , but 4096-8192-16384 is recommended");

            this._keySize = keySize;
            GenerateKey();

            if (_useMontgomery)
            {
                // Setup Montgomery multiplication , doesn't need to be saved to file?
                var (r, rInv, nInv, ks) = ComputeMontgomeryConstants(_modulus);
                _r = r;
                _rInv = rInv;
                _nInv = nInv;
                //_r = BigInteger.One << (_keySize);
                //_rInv = ModInverse(_r, _modulus);
            }
        }

        /// <summary>
        /// Initializes a new instance of the ManagedRSA class with a PKCS#12 (PFX) byte array.
        /// </summary>
        public ManagedRSA(byte[] pfxData, bool isPrivateKey = false)
        {
            FromPfx(pfxData, isPrivateKey);
            if (_useMontgomery)
            {
                var (r, rInv, nInv, ks) = ComputeMontgomeryConstants(_modulus);
                _r = r;
                _rInv = rInv;
                _nInv = nInv;
            }
        }

        /// <summary>
        /// Gets the public exponent.
        /// </summary>
        public BigInteger PublicKey => _publicKey;

        /// <summary>
        /// Gets the private exponent.
        /// </summary>
        public BigInteger PrivateKey => _privateKey;

        // Export RSA parameters
        public RSAParameters ExportParameters(bool includePrivateParameters)
        {
            var rsaParams = new RSAParameters //for encrypt/write
            {
                Modulus = _modulus.ToByteArray().Reverse().ToArray(),//256bytes  
                Exponent = _publicKey.ToByteArray().Reverse().ToArray()//small
            };


            if (includePrivateParameters && _isPrivateKeyLoaded)//for decrypt/read
            {
                rsaParams.D = _privateKey.ToByteArray().Reverse().ToArray();//in 2048: 256bytes not 255


                ////crt decrypt params for perf: all 128 bytes
                rsaParams.P = _p.ToByteArray().Reverse().ToArray();
                rsaParams.Q = _q.ToByteArray().Reverse().ToArray();
                ////
                rsaParams.DP = _dp.ToByteArray().Reverse().ToArray();
                rsaParams.DQ = _dq.ToByteArray().Reverse().ToArray();
                rsaParams.InverseQ = _qInv.ToByteArray().Reverse().ToArray();
            }

            return rsaParams;
        }
        public static explicit operator RSACng(ManagedRSA managedRsa)
        {
            return ToRSA(managedRsa, managedRsa._isPrivateKeyLoaded);
        }

        private static RSACng ToRSA(ManagedRSA managedRsa, bool includePrivateParameters)
        {
            RSAParameters rsaParams = managedRsa.ExportParameters(includePrivateParameters: includePrivateParameters);

            //CngKeyCreationParameters creationParameters = new CngKeyCreationParameters
            //{
            //    ExportPolicy = CngExportPolicies.AllowExport
            //};
            //CngKey rsaKey = CngKey.Create(CngAlgorithm.Rsa, null, creationParameters);

            RSACng rsaCng = new RSACng();//rsaKey //fix on 3072: mod&d not same size
            rsaCng.ImportParameters(rsaParams);//q-dq 191 instead of 192 on rsa 3072?

            return rsaCng;
        }

        /// <summary>
        /// Generates an RSA key pair with primes p and q.
        /// </summary>
        private void GenerateKey()
        {
            _p = PrimeGenerator.GeneratePrimeNumber(_keySize / 2);//bits/data are: uint[32] hex + sign(s) value(-1,0,1)  , t=32 is number of limbs(uints)
            _q = PrimeGenerator.GeneratePrimeNumber(_keySize / 2);//bits/data are: uint[32] hex + sign(s) value(-1,0,1) , t=32 is number of limbs(uints)

            _modulus = _p * _q;
            BigInteger phi = (_p - 1) * (_q - 1);

            if (_genPublicKey)
            {
                //no need
                _publicKey = PrimeGenerator.GetCoprime(phi);//in most rsa impl it's 0x10001 like openssl: OSSL_PKEY_PARAM_RSA_E , and RSACng key
            }
            _privateKey = ModInverse(_publicKey, phi);

            if (_useCrtDecrypt)
            {
                // Precompute values for CRT
                _dp = _privateKey % (_p - 1);
                _dq = _privateKey % (_q - 1);
                _qInv = ModInverse(_q, _p);
            }

            _isPublicKeyLoaded = true;
            _isPrivateKeyLoaded = true;
        }



        #region Montgomery
        //Montgomery exponentiation can be more efficient in performance for modular exponentiation,
        //compared to BigInteger.ModPow,
        //particularly when dealing with large integers,
        //because it reduces the number of costly division operations.of big int
        //This can lead to significant performance improvements in some cases.


        private BigInteger MontgomeryExp(BigInteger b/*value*/, BigInteger e/*exponent*/, BigInteger modulus)
        {
            return MontgomeryExp(b /*bytes*/, e, modulus, _r, _rInv, _nInv, _keySize);
        }

        private BigInteger MontgomeryReduce(BigInteger x, BigInteger modulus, BigInteger r, BigInteger nInv, int keySize)
        {
            //BigInteger m = (x * rInv) % r;
            // BigInteger m = (x * nInv) & (r - 1);// m = (t * nInv) mod r (bitwise optimization)
            BigInteger m = ((x & (r - 1)) * nInv) & (r - 1);
            BigInteger t = (x + m * modulus) >> keySize;// u = (t + m * n) / r
            if (t >= modulus)
            {
                t -= modulus;
            }

            return t;
        }

        private BigInteger MontgomeryExp(BigInteger b/*bytes*/, BigInteger e, BigInteger modulus,
            BigInteger r, BigInteger rInv, BigInteger nInv, int keySize)
        {
            //BigInteger baseR = (b * r) % modulus;
            BigInteger baseR = MontgomeryReduce(b * r, modulus, r, nInv, keySize);//convert to Montgomery form
            BigInteger x = r % modulus;

            for (int i = GetBitLength(e) - 1; i >= 0; i--)
            {
                x = MontgomeryReduce(x * x, modulus, r, nInv, keySize);//square
                if (TestBit(e, i))
                {
                    x = MontgomeryReduce(x * baseR, modulus, r, nInv, keySize);//multiply
                }
            }

            //return MontgomeryReduce(x, modulus, r, rInv, keySize);
            return MontgomeryReduce(x * rInv, modulus, r, nInv, keySize);//convert from Montgomery form
        }


        private (BigInteger r, BigInteger rInv, BigInteger nInv, int keySize) ComputeMontgomeryConstants(BigInteger modulus, int? keySize = null)
        {
            if (!keySize.HasValue)
                keySize = GetBitLength(modulus);

            BigInteger r = BigInteger.One << keySize.Value;

            BigInteger rInv = ModInverse(r, modulus);
            BigInteger nInv = -ModInverse(modulus, r);

            return (r, rInv, nInv, keySize.Value);
        }

        private static int GetBitLength(BigInteger value)
        {
            if (value.IsZero)
                return 0;

            byte[] bytes = value.ToByteArray();
            //return bytes.Length * 8;

            int bitLength = (bytes.Length - 1) * 8;
            byte mostSignificantByte = bytes[bytes.Length - 1];


            int msbBits = 8;
            while (msbBits > 0 && (mostSignificantByte & (1 << (msbBits - 1))) == 0)
            {
                msbBits--;
            }

            bitLength += msbBits;
            //return bitLength;
            return ((bitLength + 31) / 32) * 32; // Round up to nearest multiple of 32
        }


        private static bool TestBit(BigInteger value, int bit)
        {
            return (value & (BigInteger.One << bit)) != 0;
        }

        #endregion

        /// <summary>
        /// Encrypts data using RSA and OAEP padding.
        /// </summary>
        public byte[] Encrypt(byte[] data)
        {
            if (!_isPublicKeyLoaded)
                throw new InvalidOperationException("Public key is not loaded.");

            byte[] paddedData = _usePadding ? Pad(data, _keySize / 8) : data;
            var padded = Encoding.UTF8.GetString(paddedData);

            // Reverse the byte array for BigInteger to match RSA's big-endian format
            BigInteger message = new BigInteger(paddedData.Reverse().ToArray());
            BigInteger encrypted;
            if (_useMontgomery)
            {
                encrypted = MontgomeryExp(message, _publicKey, _modulus);
            }
            else
            {
                encrypted = BigInteger.ModPow(message, _publicKey, _modulus);
            }
            //return encrypted.ToByteArray();

            // Convert the encrypted BigInteger to byte array and reverse it to big-endian format
            return encrypted.ToByteArray().Reverse().ToArray();
        }

        /// <summary>
        /// Decrypts data using RSA and OAEP padding.
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData)
        {
            if (!_isPrivateKeyLoaded)
                throw new InvalidOperationException("Private key is not loaded.");

            BigInteger encrypted = new BigInteger(encryptedData.Reverse().ToArray()); //BigInteger class expects little-endian byte arrays
            //BigInteger encrypted = new BigInteger(encryptedData);

            byte[] decryptedData;

            if (_useBlinding && _useMontgomery)
            {
                // Implement blinding to protect against timing attacks
                BigInteger blindingFactor = GenerateBlindingFactor(_modulus);
                BigInteger blinded =
                    MontgomeryExp((encrypted * BigInteger.ModPow(blindingFactor, _publicKey, _modulus)) % _modulus,
                        _privateKey, _modulus);
                BigInteger unblinded = (blinded * ModInverse(blindingFactor, _modulus)) % _modulus;

                decryptedData = unblinded.ToByteArray(); //.Reverse().ToArray();
            }
            else
            {
                BigInteger decryptedDataInt;
                if (_useCrtDecrypt)
                {
                    decryptedDataInt = CRT_Decrypt(encrypted, _p, _q, _dp, _dq, _qInv); //unblinded.ToByteArray().Reverse().ToArray());
                }
                else
                {
                    if (_useMontgomery)
                    {
                        //Montgomery exponentiation for better performance
                        decryptedDataInt = MontgomeryExp(encrypted, _privateKey, _modulus);
                    }
                    else
                    {
                        // Use standard modular exponentiation(ModPow) for decryption
                        decryptedDataInt = BigInteger.ModPow(encrypted, _privateKey, _modulus);
                    }
                }
                decryptedData = decryptedDataInt.ToByteArray().Reverse().ToArray();
                //decryptedData = decryptedDataInt.ToByteArray();
            }

            return _usePadding ? Unpad(decryptedData) : decryptedData;
        }
        private byte[] Pad(byte[] data, int length)
        {
            return _useOaep ? OAEP_Pad(data, length) : PKCS1Pad(data, length);
        }
        private byte[] Unpad(byte[] paddedData)
        {
            return _useOaep ? OAEP_Unpad(paddedData) : PKCS1Unpad(paddedData);
        }

        /// <summary>
        /// Optimized decryption using the Chinese Remainder Theorem (CRT).
        /// by splitting the decryption operation into smaller parts that are more efficient to compute
        /// </summary>
        private BigInteger CRT_Decrypt(BigInteger c/*encryptedData*/,
            BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv)
        {
            if (!_isPrivateKeyLoaded)
                throw new InvalidOperationException("Private key is not loaded.");
            // var arr = encryptedData.Reverse().ToArray();//needed? no

            //BigInteger c = new BigInteger(encryptedData);

            BigInteger m1;
            BigInteger m2;

            if (_useMontgomery)
            {
                var (rp, rInvP, rnInvP, keySizeP) = ComputeMontgomeryConstants(p);//slow , // Precompute on ctor instead on decrypt
                var (rq, rInvQ, rnInvQ, keySizeQ) = ComputeMontgomeryConstants(q);

                m1 = MontgomeryExp(c, dP, p, rp, rInvP, rnInvP, keySizeP);
                m2 = MontgomeryExp(c, dQ, q, rq, rInvQ, rnInvQ, keySizeQ);
            }
            else
            {
                m1 = BigInteger.ModPow(c, dP, p);
                m2 = BigInteger.ModPow(c, dQ, q);
            }

            BigInteger h = (qInv * (m1 - m2)) % p;
            if (h < 0)
                h += p;

            BigInteger m = m2 + h * q;
            return m; //.ToByteArray();//.Reverse().ToArray();
        }

        #region Padding


        //PKCS#1 v1.5 Padding
        //        introduces random bytes, which won't be present after decryption.
        // However, the random padding is not part of the original message;
        // it's only there to ensure security by making each encryption operation
        // produce a unique ciphertext for the same plaintext.
        private byte[] PKCS1Pad(byte[] data, int blockSize)
        {
            if (data.Length > blockSize - 11)
                throw new ArgumentException("Data too long for encryption block.");

            byte[] paddedData = new byte[blockSize];
            paddedData[0] = 0x00; // Leading zero
            paddedData[1] = 0x02; // Type 2 padding

            // Calculate the length of the padding
            int paddingLength = blockSize - data.Length - 3;
            if (paddingLength < 8)
                throw new ArgumentException("Block size too small for PKCS#1 v1.5 padding.");

            // Fill padding with non-zero random bytes
            RandomNumberGenerator.Fill(paddedData.AsSpan(2, paddingLength));
            for (int i = 2; i < paddingLength + 2; i++)
            {
                while (paddedData[i] == 0)
                    RandomNumberGenerator.Fill(paddedData.AsSpan(i, 1)); // Ensure non-zero padding
            }

            paddedData[paddingLength + 2] = 0x00; // Separator byte
            Array.Copy(data, 0, paddedData, paddingLength + 3, data.Length);
            return paddedData;
        }


        private byte[] PKCS1Unpad(byte[] paddedData)
        {
            //leading zero byte (0x00) might be lost because of how BigInteger handles the conversion.

            // Ensure the leading zero byte is present
            if (paddedData[0] != 0x00)
            {
                byte[] temp = new byte[paddedData.Length + 1];
                temp[0] = 0x00;
                Array.Copy(paddedData, 0, temp, 1, paddedData.Length);
                paddedData = temp;
            }

            if (paddedData[0] != 0x00 || paddedData[1] != 0x02)
                throw new ArgumentException("Invalid padding.");

            int i = 2;
            while (i < paddedData.Length && paddedData[i] != 0x00) i++;
            if (i == paddedData.Length)
                throw new ArgumentException("Invalid padding.");

            i++; // Skip the 0x00 byte
            byte[] data = new byte[paddedData.Length - i];
            Array.Copy(paddedData, i, data, 0, data.Length);

            return data;
        }

        /// <summary>
        /// Applies OAEP padding to the input data.
        /// </summary>
        private byte[] OAEP_Pad(byte[] data, int length)
        {
            if (data.Length > length - 2 * 64 - 2)
                throw new ArgumentException("Data too long.");

            byte[] padded = new byte[length];
            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] lHash = sha512.ComputeHash(new byte[0]);
                byte[] ps = new byte[length - data.Length - 2 * lHash.Length - 2];
                byte[] db = new byte[lHash.Length + ps.Length + 1 + data.Length];


                Array.Copy(lHash, 0, db, 0, lHash.Length);
                Array.Copy(ps, 0, db, lHash.Length, ps.Length);

                db[lHash.Length + ps.Length] = 0x01;
                Array.Copy(data, 0, db, lHash.Length + ps.Length + 1, data.Length);

                byte[] seed = new byte[lHash.Length];
                RandomNumberGenerator.Fill(seed);

                byte[] dbMask = MGF1(seed, db.Length, sha512);
                for (int i = 0; i < db.Length; i++)
                {
                    db[i] ^= dbMask[i];
                }

                byte[] seedMask = MGF1(db, seed.Length, sha512);
                for (int i = 0; i < seed.Length; i++)
                {
                    seed[i] ^= seedMask[i];
                }

                Array.Copy(seed, 0, padded, 1, seed.Length);
                Array.Copy(db, 0, padded, seed.Length + 1, db.Length);
            }

            return padded;
        }


        /// <summary>
        /// Removes OAEP padding from the input data.
        /// </summary>
        private byte[] OAEP_Unpad(byte[] data)
        {
            // Ensure the leading zero byte is present
            //if (data[0] != 0x00)
            //{
            //    byte[] temp = new byte[data.Length + 1];
            //    temp[0] = 0x00;
            //    Array.Copy(data, 0, temp, 1, data.Length);
            //    data = temp;
            //}

            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] lHash = sha512.ComputeHash(new byte[0]);
                int hashLength = lHash.Length;
                byte[] seed = new byte[hashLength];
                Array.Copy(data, 1, seed, 0, hashLength);

                byte[] db = new byte[data.Length - hashLength - 1];
                Array.Copy(data, hashLength + 1, db, 0, db.Length);

                byte[] seedMask = MGF1(db, seed.Length, sha512);
                for (int i = 0; i < seed.Length; i++)
                {
                    seed[i] ^= seedMask[i];
                }

                byte[] dbMask = MGF1(seed, db.Length, sha512);
                for (int i = 0; i < db.Length; i++)
                {
                    db[i] ^= dbMask[i];
                }

                byte[] lHash2 = new byte[hashLength];
                Array.Copy(db, 0, lHash2, 0, hashLength);

                if (!ConstantTimeComparer.FixedTimeEquals(lHash, lHash2))//fix: padding has issues
                {
                    throw new CryptographicException("Decryption failed.");
                }

                int index = hashLength;
                while (db[index] != 0x01)
                {
                    index++;
                }

                index++;

                byte[] message = new byte[db.Length - index];
                Array.Copy(db, index, message, 0, message.Length);

                return message;
            }
        }

        /// <summary>
        /// Mask Generation Function (MGF1) based on a hash function.
        /// </summary>
        private byte[] MGF1(byte[] seed, int length, HashAlgorithm hash)
        {
            byte[] mask = new byte[length];
            byte[] counter = BitConverter.GetBytes(0);
            int hashLength = hash.HashSize / 8;

            for (int i = 0; i < length; i += hashLength)
            {
                byte[] hashInput = new byte[seed.Length + 4];
                Buffer.BlockCopy(seed, 0, hashInput, 0, seed.Length);
                Buffer.BlockCopy(counter, 0, hashInput, seed.Length, 4);
                byte[] hashOutput = hash.ComputeHash(hashInput);//use sha3 512, safer

                Buffer.BlockCopy(hashOutput, 0, mask, i, Math.Min(hashLength, length - i));

                for (int j = 3; j >= 0; j--)
                {
                    if (++counter[j] != 0)
                        break;
                }
            }

            return mask;
        }
        #endregion

        /// <summary>
        /// Computes the modular inverse of a number.
        /// </summary>
        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            (BigInteger gcd, BigInteger x, _) = ExtendedGCD(a, m);
            if (gcd != 1)
            {
                throw new ArgumentException("No modular inverse exists");
            }

            return (x % m + m) % m;
        }

        /// <summary>
        /// Computes the extended Euclidean algorithm. recursivley
        /// </summary>
        private static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGCD(BigInteger a, BigInteger b)
        {
            if (b == 0)
            {
                return (a, 1, 0);
            }

            (BigInteger gcd, BigInteger x1, BigInteger y1) = ExtendedGCD(b, a % b);//use tail recursion to avoid stack overflows? 
            BigInteger x = y1;
            BigInteger y = x1 - (a / b) * y1;
            return (gcd, x, y);

            /* iterative impl:
    BigInteger x0 = 1, xn = 0;
    BigInteger y0 = 0, yn = 1;

    while (b != 0)
    {
        BigInteger quotient = a / b;
        BigInteger remainder = a % b;

        a = b;
        b = remainder;

        BigInteger xTemp = xn;
        xn = x0 - quotient * xn;
        x0 = xTemp;

        BigInteger yTemp = yn;
        yn = y0 - quotient * yn;
        y0 = yTemp;
    }

    return (a, x0, y0);

            private BigInteger ModInverse(BigInteger a, BigInteger modulus)
{
    BigInteger m0 = modulus, t, q;
    BigInteger x0 = BigInteger.Zero, x1 = BigInteger.One;

    if (modulus == BigInteger.One)
        return BigInteger.Zero;

    while (a > BigInteger.One)
    {
        // q is quotient
        q = a / modulus;

        t = modulus;

        // m is remainder now, process same as Euclid's algo
        modulus = a % modulus;
        a = t;

        t = x0;

        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < BigInteger.Zero)
        x1 += m0;

    return x1;
}
             */
        }

        /// <summary>
        /// Generates a blinding factor to protect against timing attacks.
        /// </summary>
        private BigInteger GenerateBlindingFactor(BigInteger modulus)
        {
            byte[] buffer = new byte[modulus.GetByteCount()];
            RandomNumberGenerator.Fill(buffer);
            BigInteger blindingFactor = new BigInteger(buffer);
            return BigInteger.ModPow(blindingFactor, _publicKey, modulus);
        }

        /// <summary>
        /// Disposes the ManagedRSA instance.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _privateKey = BigInteger.Zero;
                _publicKey = BigInteger.Zero;
                _modulus = BigInteger.Zero;
                //
                _p = BigInteger.Zero;
                _q = BigInteger.Zero;
                //
                _dp = BigInteger.Zero;
                _dq = BigInteger.Zero;
                _qInv = BigInteger.Zero;
                //
                _r = BigInteger.Zero;
                _rInv = BigInteger.Zero;
                _nInv = BigInteger.Zero;
                //
                _isPublicKeyLoaded = false;
                _isPrivateKeyLoaded = false;
                //
                _disposed = true;
            }
        }
    }
}