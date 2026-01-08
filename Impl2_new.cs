/*
 * EDUCATIONAL RSA IMPLEMENTATION (Reference Quality - Merged Final)
 * ==================================================================
 * Target: .NET 7+ (recommended .NET 8/9/10)
 *
 * Standards Implemented:
 *   - PKCS #1 v2.2 (RFC 8017) - RSAES-OAEP, RSAES-PKCS1-v1_5
 *   - NIST SP 800-56B Rev. 2 - Key Generation Guidelines
 *
 * Security Features:
 *   - Constant-Time Unpadding (OAEP & PKCS#1 v1.5) to mitigate Padding Oracle Attacks
 *   - MGF1 with Big-Endian Counter (RFC 8017 §B.2.1)
 *   - CRT Decryption with Blinding (Mitigates timing side-channels)
 *   - Miller-Rabin Primality Testing (40+ rounds, error < 2^-80)
 *   - ASN.1 DER Import/Export (PKCS#1, PKCS#8, SPKI - OpenSSL compatible)
 *
 * References:
 *   - RFC 8017: https://www.rfc-editor.org/rfc/rfc8017
 *   - NIST SP 800-56B: https://csrc.nist.gov/publications/detail/sp/800-56b/rev-2/final
 *
 * WARNING: This is for EDUCATIONAL purposes. For production, use RSA.Create() or
 *          a vetted library. BigInteger operations are NOT constant-time.
 */

#nullable enable
using System;
using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace EducationalCrypto.RSA
{
    // =========================================================================
    // 1. BIG INTEGER CODEC (RFC 8017 §4 - I2OSP / OS2IP)
    // =========================================================================
    internal static class BigIntCodec
    {
        /// <summary>
        /// OS2IP: Octet String to Integer Primitive (RFC 8017 §4.2)
        /// Converts big-endian unsigned bytes to a non-negative BigInteger.
        /// </summary>
        public static BigInteger OS2IP(ReadOnlySpan<byte> data)
            => new BigInteger(data, isUnsigned: true, isBigEndian: true);

        /// <summary>
        /// I2OSP: Integer to Octet String Primitive (RFC 8017 §4.1)
        /// Converts a non-negative BigInteger to exactly 'size' big-endian bytes.
        /// </summary>
        public static byte[] I2OSP(BigInteger x, int size)
        {
            if (x.Sign < 0)
                throw new CryptographicException("I2OSP: Negative integer not allowed.");

            byte[] raw = x.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (raw.Length > size)
                throw new CryptographicException("I2OSP: Integer too large for specified size.");

            if (raw.Length == size)
                return raw;

            // Left-pad with zeros
            byte[] padded = new byte[size];
            Buffer.BlockCopy(raw, 0, padded, size - raw.Length, raw.Length);
            return padded;
        }

        /// <summary>
        /// Returns the bit length of a positive BigInteger.
        /// </summary>
        public static int BitLength(BigInteger n)
        {
            if (n.Sign <= 0) return 0;
            return (int)n.GetBitLength();
        }

        /// <summary>
        /// Extended Euclidean Algorithm for modular inverse.
        /// </summary>
        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            a %= m;
            if (a.Sign < 0) a += m;

            BigInteger t = 0, newT = 1;
            BigInteger r = m, newR = a;

            while (!newR.IsZero)
            {
                BigInteger q = r / newR;
                (t, newT) = (newT, t - q * newT);
                (r, newR) = (newR, r - q * newR);
            }

            if (r != 1)
                throw new CryptographicException("ModInverse: Value not invertible.");
            if (t.Sign < 0)
                t += m;

            return t;
        }

        /// <summary>
        /// Least Common Multiple (for Carmichael's totient).
        /// </summary>
        public static BigInteger Lcm(BigInteger a, BigInteger b)
            => (a / BigInteger.GreatestCommonDivisor(a, b)) * b;
    }

    // =========================================================================
    // 2. HASH UTILITIES
    // =========================================================================
    internal static class HashUtil
    {
        public static int HashLen(HashAlgorithmName alg) => alg.Name switch
        {
            "SHA1" => 20,
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException($"Hash algorithm not supported: {alg.Name}")
        };

        public static byte[] HashData(HashAlgorithmName alg, ReadOnlySpan<byte> data) => alg.Name switch
        {
            "SHA1" => SHA1.HashData(data),
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"Hash algorithm not supported: {alg.Name}")
        };
    }

    // =========================================================================
    // 3. PRIME GENERATION (Miller-Rabin with Unbiased Sampling)
    // =========================================================================
    internal static class PrimeGenerator
    {
        private static readonly int[] SmallPrimes =
        {
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
            59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
            113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
            179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
            307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367,
            373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
            439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
            503, 509, 521, 523, 541
        };

        /// <summary>
        /// Generates a random prime of exactly 'bits' bit-length.
        /// </summary>
        public static BigInteger GeneratePrime(int bits, int mrRounds = 40)
        {
            if (bits < 2)
                throw new ArgumentOutOfRangeException(nameof(bits), "Bit length must be >= 2.");

            int byteLen = (bits + 7) / 8;

            // Use stackalloc for reasonable sizes, heap for large keys
            Span<byte> buffer = byteLen <= 512 ? stackalloc byte[byteLen] : new byte[byteLen];

            while (true)
            {
                RandomNumberGenerator.Fill(buffer);

                // Mask excess high bits to ensure exact bit length
                int excessBits = byteLen * 8 - bits;
                buffer[0] &= (byte)(0xFF >> excessBits);

                // Force MSB = 1 to ensure exact bit-length
                buffer[0] |= (byte)(1 << (7 - excessBits));

                // Force odd (LSB = 1)
                buffer[^1] |= 0x01;

                BigInteger candidate = BigIntCodec.OS2IP(buffer);

                if (candidate < 3) continue;

                // Trial division by small primes
                bool divisible = false;
                foreach (int p in SmallPrimes)
                {
                    if (candidate == p) return candidate; // It IS a small prime
                    if (candidate % p == 0) { divisible = true; break; }
                }
                if (divisible) continue;

                if (IsProbablePrimeMillerRabin(candidate, mrRounds))
                    return candidate;
            }
        }

        /// <summary>
        /// Miller-Rabin primality test with random bases.
        /// </summary>
        public static bool IsProbablePrimeMillerRabin(BigInteger n, int rounds)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n.IsEven) return false;

            // Write n-1 = d * 2^s with d odd
            BigInteger d = n - 1;
            int s = 0;
            while (d.IsEven) { d >>= 1; s++; }

            for (int i = 0; i < rounds; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1) continue;

                bool composite = true;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1) { composite = false; break; }
                }

                if (composite) return false;
            }

            return true;
        }

        /// <summary>
        /// Unbiased random in [minInclusive, maxInclusive].
        /// </summary>
        public static BigInteger RandomInRange(BigInteger minInclusive, BigInteger maxInclusive)
        {
            if (minInclusive > maxInclusive)
                throw new ArgumentException("min > max");

            BigInteger span = maxInclusive - minInclusive + 1;
            return minInclusive + RandomBelow(span);
        }

        /// <summary>
        /// Rejection-sampling random in [0, maxExclusive).
        /// </summary>
        private static BigInteger RandomBelow(BigInteger maxExclusive)
        {
            if (maxExclusive <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxExclusive));

            int bits = BigIntCodec.BitLength(maxExclusive - 1);
            if (bits == 0) bits = 1;
            int byteLen = (bits + 7) / 8;

            Span<byte> buffer = byteLen <= 512 ? stackalloc byte[byteLen] : new byte[byteLen];

            while (true)
            {
                RandomNumberGenerator.Fill(buffer);

                // Mask excess high bits to reduce rejection rate
                int excessBits = byteLen * 8 - bits;
                if (excessBits > 0)
                    buffer[0] &= (byte)(0xFF >> excessBits);

                BigInteger x = BigIntCodec.OS2IP(buffer);
                if (x < maxExclusive) return x;
            }
        }

        /// <summary>
        /// Generates a random value coprime to n (for RSA blinding).
        /// </summary>
        public static BigInteger GenerateCoprime(BigInteger n)
        {
            while (true)
            {
                BigInteger r = RandomInRange(2, n - 2);
                if (BigInteger.GreatestCommonDivisor(r, n) == 1)
                    return r;
            }
        }
    }

    // =========================================================================
    // 4. PADDING SCHEMES (RFC 8017 §7)
    // =========================================================================
    internal static class PaddingHelper
    {
        // =====================================================================
        // MGF1 - Mask Generation Function (RFC 8017 §B.2.1)
        // =====================================================================
        private static byte[] Mgf1(HashAlgorithmName hash, ReadOnlySpan<byte> seed, int maskLen)
        {
            int hLen = HashUtil.HashLen(hash);
            byte[] mask = new byte[maskLen];
            byte[] input = new byte[seed.Length + 4];
            seed.CopyTo(input);

            Span<byte> counterBytes = input.AsSpan(seed.Length, 4);

            int offset = 0;
            for (uint counter = 0; offset < maskLen; counter++)
            {
                // RFC 8017 §B.2.1: counter is 4-octet BIG-ENDIAN
                BinaryPrimitives.WriteUInt32BigEndian(counterBytes, counter);

                byte[] digest = HashUtil.HashData(hash, input);
                int copyLen = Math.Min(hLen, maskLen - offset);
                Buffer.BlockCopy(digest, 0, mask, offset, copyLen);
                offset += hLen;
            }

            return mask;
        }

        // =====================================================================
        // OAEP Encoding (RFC 8017 §7.1.1)
        // =====================================================================
        public static byte[] OaepEncode(ReadOnlySpan<byte> message, int k, HashAlgorithmName hash, ReadOnlySpan<byte> label = default)
        {
            int hLen = HashUtil.HashLen(hash);

            int maxMsgLen = k - 2 * hLen - 2;
            if (message.Length > maxMsgLen)
                throw new CryptographicException($"Message too long. Max: {maxMsgLen} bytes.");

            byte[] lHash = HashUtil.HashData(hash, label);

            int psLen = k - message.Length - 2 * hLen - 2;

            // DB = lHash || PS || 0x01 || M
            byte[] DB = new byte[k - hLen - 1];
            Buffer.BlockCopy(lHash, 0, DB, 0, hLen);
            DB[hLen + psLen] = 0x01;
            message.CopyTo(DB.AsSpan(hLen + psLen + 1));

            byte[] seed = new byte[hLen];
            RandomNumberGenerator.Fill(seed);

            byte[] dbMask = Mgf1(hash, seed, DB.Length);
            for (int i = 0; i < DB.Length; i++)
                DB[i] ^= dbMask[i];

            byte[] seedMask = Mgf1(hash, DB, hLen);
            for (int i = 0; i < seed.Length; i++)
                seed[i] ^= seedMask[i];

            // EM = 0x00 || maskedSeed || maskedDB
            byte[] EM = new byte[k];
            EM[0] = 0x00;
            Buffer.BlockCopy(seed, 0, EM, 1, hLen);
            Buffer.BlockCopy(DB, 0, EM, 1 + hLen, DB.Length);

            return EM;
        }

        // =====================================================================
        // OAEP Decoding - Constant-Time (RFC 8017 §7.1.2)
        // =====================================================================
        public static byte[] OaepDecode(ReadOnlySpan<byte> EM, HashAlgorithmName hash, ReadOnlySpan<byte> label = default)
        {
            int k = EM.Length;
            int hLen = HashUtil.HashLen(hash);

            if (k < 2 * hLen + 2)
                throw new CryptographicException("Decryption failed.");

            int bad = 0;
            bad |= EM[0]; // Y must be 0x00

            byte[] maskedSeed = EM.Slice(1, hLen).ToArray();
            byte[] maskedDB = EM.Slice(1 + hLen).ToArray();

            byte[] seedMask = Mgf1(hash, maskedDB, hLen);
            byte[] seed = new byte[hLen];
            for (int i = 0; i < hLen; i++)
                seed[i] = (byte)(maskedSeed[i] ^ seedMask[i]);

            byte[] dbMask = Mgf1(hash, seed, maskedDB.Length);
            byte[] DB = new byte[maskedDB.Length];
            for (int i = 0; i < DB.Length; i++)
                DB[i] = (byte)(maskedDB[i] ^ dbMask[i]);

            byte[] lHashExpected = HashUtil.HashData(hash, label);

            if (!CryptographicOperations.FixedTimeEquals(
                    new ReadOnlySpan<byte>(DB, 0, hLen), lHashExpected))
                bad |= 1;

            // Find 0x01 delimiter (constant-time scan)
            int foundOne = 0;
            int oneIndex = 0;

            for (int i = hLen; i < DB.Length; i++)
            {
                byte b = DB[i];
                int isZero = (b == 0x00) ? 1 : 0;
                int isOne = (b == 0x01) ? 1 : 0;

                // Before finding 0x01, only 0x00 is allowed
                int isInvalid = (foundOne ^ 1) & (isZero ^ 1) & (isOne ^ 1);
                bad |= isInvalid;

                int firstOneMask = (foundOne ^ 1) & isOne;
                oneIndex |= i * firstOneMask;
                foundOne |= firstOneMask;
            }

            bad |= (foundOne ^ 1);

            if (bad != 0)
                throw new CryptographicException("Decryption failed.");

            int msgStart = oneIndex + 1;
            byte[] msg = new byte[DB.Length - msgStart];
            Buffer.BlockCopy(DB, msgStart, msg, 0, msg.Length);
            return msg;
        }

        // =====================================================================
        // PKCS#1 v1.5 Encoding (RFC 8017 §7.2.1)
        // =====================================================================
        public static byte[] Pkcs1v15Encode(ReadOnlySpan<byte> message, int k)
        {
            if (message.Length > k - 11)
                throw new CryptographicException("Message too long for PKCS#1 v1.5 padding.");

            byte[] EM = new byte[k];
            EM[0] = 0x00;
            EM[1] = 0x02;

            int psLen = k - message.Length - 3;
            if (psLen < 8)
                throw new CryptographicException("Key too short for PKCS#1 v1.5 padding.");

            Span<byte> PS = EM.AsSpan(2, psLen);
            RandomNumberGenerator.Fill(PS);

            // Ensure all PS bytes are non-zero
            for (int i = 0; i < PS.Length; i++)
            {
                while (PS[i] == 0)
                {
                    Span<byte> single = stackalloc byte[1];
                    RandomNumberGenerator.Fill(single);
                    PS[i] = single[0];
                }
            }

            EM[2 + psLen] = 0x00;
            message.CopyTo(EM.AsSpan(3 + psLen));

            return EM;
        }

        // =====================================================================
        // PKCS#1 v1.5 Decoding - Constant-Time (RFC 8017 §7.2.2)
        // =====================================================================
        public static byte[] Pkcs1v15Decode(ReadOnlySpan<byte> EM)
        {
            int k = EM.Length;
            if (k < 11)
                throw new CryptographicException("Decryption failed.");

            int bad = 0;
            bad |= EM[0];           // must be 0x00
            bad |= EM[1] ^ 0x02;    // must be 0x02

            // Find FIRST 0x00 byte (the separator)
            int foundSep = 0;
            int sepIndex = 0;

            for (int i = 2; i < k; i++)
            {
                int isZero = (EM[i] == 0x00) ? 1 : 0;
                int isFirstZero = (foundSep ^ 1) & isZero;
                sepIndex |= i * isFirstZero;
                foundSep |= isFirstZero;
            }

            bad |= (foundSep ^ 1);
            bad |= (sepIndex < 10) ? 1 : 0; // PS >= 8 bytes

            if (bad != 0)
                throw new CryptographicException("Decryption failed.");

            int msgStart = sepIndex + 1;
            byte[] msg = new byte[k - msgStart];
            EM.Slice(msgStart).CopyTo(msg);
            return msg;
        }
    }

    // =========================================================================
    // 5. MANAGED RSA IMPLEMENTATION
    // =========================================================================
    public sealed class ManagedRsa : IDisposable
    {
        private BigInteger _n;    // Modulus
        private BigInteger _e;    // Public exponent
        private BigInteger _d;    // Private exponent
        private BigInteger _p, _q;           // Prime factors
        private BigInteger _dp, _dq, _qInv;  // CRT components

        public int KeySizeBits { get; private set; }
        public int ModulusBytes => (KeySizeBits + 7) / 8;

        public bool HasPublicKey => !_n.IsZero && !_e.IsZero;
        public bool HasPrivateKey => !_d.IsZero;

        public bool UseCrt { get; set; } = true;
        public bool UseBlinding { get; set; } = true;

        public BigInteger Modulus => _n;
        public BigInteger PublicExponent => _e;

        private bool _disposed;

        public static readonly BigInteger DefaultPublicExponent = 65537;

        // =====================================================================
        // Constructors
        // =====================================================================
        public ManagedRsa(int keySizeBits = 2048, BigInteger? publicExponent = null, int mrRounds = 40)
        {
            if (keySizeBits < 2048)
                throw new ArgumentException("Key size must be >= 2048 bits for security.", nameof(keySizeBits));

            _e = publicExponent ?? DefaultPublicExponent;
            GenerateKeyPair(keySizeBits, mrRounds);
        }

        public ManagedRsa(RSAParameters parameters) => ImportParameters(parameters);

        public ManagedRsa(string pem) => ImportPem(pem);

        private ManagedRsa() { } // For FromRSA

        // =====================================================================
        // Key Generation (NIST SP 800-56B)
        // =====================================================================
        private void GenerateKeyPair(int keySizeBits, int mrRounds)
        {
            while (true)
            {
                int pBits = keySizeBits / 2;
                int qBits = keySizeBits - pBits;

                BigInteger p = PrimeGenerator.GeneratePrime(pBits, mrRounds);
                BigInteger q;
                do { q = PrimeGenerator.GeneratePrime(qBits, mrRounds); } while (q == p);

                BigInteger n = p * q;
                if (BigIntCodec.BitLength(n) != keySizeBits) continue;

                // λ(n) = lcm(p-1, q-1) - Carmichael's totient (NIST recommended)
                BigInteger lambda = BigIntCodec.Lcm(p - 1, q - 1);

                if (BigInteger.GreatestCommonDivisor(_e, lambda) != 1) continue;

                BigInteger d = BigIntCodec.ModInverse(_e, lambda);

                _p = p; _q = q; _n = n; _d = d;
                _dp = d % (p - 1);
                _dq = d % (q - 1);
                _qInv = BigIntCodec.ModInverse(q, p);

                KeySizeBits = keySizeBits;
                return;
            }
        }

        // =====================================================================
        // RSAES-OAEP (RFC 8017 §7.1)
        // =====================================================================
        public byte[] EncryptOaep(ReadOnlySpan<byte> message, HashAlgorithmName hash, ReadOnlySpan<byte> label = default)
        {
            RequirePublic();
            int k = ModulusBytes;

            byte[] em = PaddingHelper.OaepEncode(message, k, hash, label);
            BigInteger m = BigIntCodec.OS2IP(em);

            BigInteger c = BigInteger.ModPow(m, _e, _n);
            return BigIntCodec.I2OSP(c, k);
        }

        public byte[] DecryptOaep(ReadOnlySpan<byte> ciphertext, HashAlgorithmName hash, ReadOnlySpan<byte> label = default)
        {
            RequirePrivate();
            int k = ModulusBytes;

            if (ciphertext.Length != k)
                throw new CryptographicException("Decryption failed.");

            BigInteger c = BigIntCodec.OS2IP(ciphertext);
            if (c >= _n)
                throw new CryptographicException("Decryption failed.");

            BigInteger m = UseBlinding ? RsaPrivateBlinded(c) : RsaPrivate(c);
            byte[] em = BigIntCodec.I2OSP(m, k);

            return PaddingHelper.OaepDecode(em, hash, label);
        }

        // =====================================================================
        // RSAES-PKCS1-v1_5 (RFC 8017 §7.2) - Legacy
        // =====================================================================
        public byte[] EncryptPkcs1v15(ReadOnlySpan<byte> message)
        {
            RequirePublic();
            int k = ModulusBytes;

            byte[] em = PaddingHelper.Pkcs1v15Encode(message, k);
            BigInteger m = BigIntCodec.OS2IP(em);

            BigInteger c = BigInteger.ModPow(m, _e, _n);
            return BigIntCodec.I2OSP(c, k);
        }

        public byte[] DecryptPkcs1v15(ReadOnlySpan<byte> ciphertext)
        {
            RequirePrivate();
            int k = ModulusBytes;

            if (ciphertext.Length != k)
                throw new CryptographicException("Decryption failed.");

            BigInteger c = BigIntCodec.OS2IP(ciphertext);
            if (c >= _n)
                throw new CryptographicException("Decryption failed.");

            BigInteger m = UseBlinding ? RsaPrivateBlinded(c) : RsaPrivate(c);
            byte[] em = BigIntCodec.I2OSP(m, k);

            return PaddingHelper.Pkcs1v15Decode(em);
        }

        // =====================================================================
        // RSA Primitives (CRT + Blinding)
        // =====================================================================
        private BigInteger RsaPrivate(BigInteger c)
        {
            if (UseCrt && !_p.IsZero && !_q.IsZero)
            {
                // Garner's CRT algorithm
                BigInteger m1 = BigInteger.ModPow(c % _p, _dp, _p);
                BigInteger m2 = BigInteger.ModPow(c % _q, _dq, _q);

                BigInteger h = (_qInv * (m1 - m2)) % _p;
                if (h.Sign < 0) h += _p;

                return m2 + _q * h;
            }

            return BigInteger.ModPow(c, _d, _n);
        }

        private BigInteger RsaPrivateBlinded(BigInteger c)
        {
            BigInteger r = PrimeGenerator.GenerateCoprime(_n);
            BigInteger rInv = BigIntCodec.ModInverse(r, _n);
            BigInteger rPowE = BigInteger.ModPow(r, _e, _n);

            BigInteger cBlinded = (c * rPowE) % _n;
            BigInteger mBlinded = RsaPrivate(cBlinded);

            BigInteger m = (mBlinded * rInv) % _n;
            if (m.Sign < 0) m += _n;
            return m;
        }

        // =====================================================================
        // RSAParameters Import/Export
        // =====================================================================
        public RSAParameters ExportParameters(bool includePrivate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            int k = ModulusBytes;
            int halfK = (k + 1) / 2;

            var parameters = new RSAParameters
            {
                Modulus = BigIntCodec.I2OSP(_n, k),
                Exponent = _e.ToByteArray(isUnsigned: true, isBigEndian: true)
            };

            if (includePrivate)
            {
                if (!HasPrivateKey)
                    throw new InvalidOperationException("No private key available.");

                parameters.D = BigIntCodec.I2OSP(_d, k);

                if (!_p.IsZero && !_q.IsZero)
                {
                    parameters.P = BigIntCodec.I2OSP(_p, halfK);
                    parameters.Q = BigIntCodec.I2OSP(_q, halfK);
                    parameters.DP = BigIntCodec.I2OSP(_dp, halfK);
                    parameters.DQ = BigIntCodec.I2OSP(_dq, halfK);
                    parameters.InverseQ = BigIntCodec.I2OSP(_qInv, halfK);
                }
            }

            return parameters;
        }

        public void ImportParameters(RSAParameters parameters)
        {
            if (parameters.Modulus == null || parameters.Exponent == null)
                throw new ArgumentException("Modulus and Exponent are required.");

            _n = BigIntCodec.OS2IP(parameters.Modulus);
            _e = BigIntCodec.OS2IP(parameters.Exponent);
            KeySizeBits = BigIntCodec.BitLength(_n);

            if (parameters.D != null)
            {
                _d = BigIntCodec.OS2IP(parameters.D);

                if (parameters.P != null) _p = BigIntCodec.OS2IP(parameters.P);
                if (parameters.Q != null) _q = BigIntCodec.OS2IP(parameters.Q);
                if (parameters.DP != null) _dp = BigIntCodec.OS2IP(parameters.DP);
                if (parameters.DQ != null) _dq = BigIntCodec.OS2IP(parameters.DQ);
                if (parameters.InverseQ != null) _qInv = BigIntCodec.OS2IP(parameters.InverseQ);
            }
        }

        // =====================================================================
        // ASN.1 DER Export
        // =====================================================================
        private static readonly string RsaEncryptionOid = "1.2.840.113549.1.1.1";

        public byte[] ExportPkcs1PublicKeyDer()
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            w.PushSequence();
            w.WriteIntegerUnsigned(_n.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_e.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.PopSequence();
            return w.Encode();
        }

        public byte[] ExportPkcs1PrivateKeyDer()
        {
            RequirePrivate();

            var w = new AsnWriter(AsnEncodingRules.DER);
            w.PushSequence();
            w.WriteInteger(0); // version

            w.WriteIntegerUnsigned(_n.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_e.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_d.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_p.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_q.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_dp.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_dq.ToByteArray(isUnsigned: true, isBigEndian: true));
            w.WriteIntegerUnsigned(_qInv.ToByteArray(isUnsigned: true, isBigEndian: true));

            w.PopSequence();
            return w.Encode();
        }

        public byte[] ExportSubjectPublicKeyInfoDer()
        {
            byte[] rsaPub = ExportPkcs1PublicKeyDer();

            var w = new AsnWriter(AsnEncodingRules.DER);
            w.PushSequence();

            w.PushSequence();
            w.WriteObjectIdentifier(RsaEncryptionOid);
            w.WriteNull();
            w.PopSequence();

            w.WriteBitString(rsaPub);
            w.PopSequence();

            return w.Encode();
        }

        public byte[] ExportPkcs8PrivateKeyInfoDer()
        {
            RequirePrivate();
            byte[] pkcs1 = ExportPkcs1PrivateKeyDer();

            var w = new AsnWriter(AsnEncodingRules.DER);
            w.PushSequence();
            w.WriteInteger(0);

            w.PushSequence();
            w.WriteObjectIdentifier(RsaEncryptionOid);
            w.WriteNull();
            w.PopSequence();

            w.WriteOctetString(pkcs1);
            w.PopSequence();

            return w.Encode();
        }

        // =====================================================================
        // ASN.1 DER Import
        // =====================================================================
        public void ImportPkcs1PublicKeyDer(ReadOnlySpan<byte> der)
        {
            var r = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var seq = r.ReadSequence();

            _n = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _e = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);

            seq.ThrowIfNotEmpty();
            r.ThrowIfNotEmpty();

            KeySizeBits = BigIntCodec.BitLength(_n);
            _d = _p = _q = _dp = _dq = _qInv = BigInteger.Zero;
        }

        public void ImportPkcs1PrivateKeyDer(ReadOnlySpan<byte> der)
        {
            var r = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var seq = r.ReadSequence();

            BigInteger version = seq.ReadInteger();
            if (version != 0)
                throw new CryptographicException("Unsupported RSAPrivateKey version.");

            _n = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _e = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _d = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _p = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _q = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _dp = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _dq = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);
            _qInv = BigIntCodec.OS2IP(seq.ReadIntegerBytes().Span);

            seq.ThrowIfNotEmpty();
            r.ThrowIfNotEmpty();

            KeySizeBits = BigIntCodec.BitLength(_n);
        }

        public void ImportSubjectPublicKeyInfoDer(ReadOnlySpan<byte> der)
        {
            var r = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var spki = r.ReadSequence();

            var algId = spki.ReadSequence();
            string oid = algId.ReadObjectIdentifier();
            if (oid != RsaEncryptionOid)
                throw new CryptographicException("Not an RSA public key.");
            if (algId.HasData) algId.ReadNull();
            algId.ThrowIfNotEmpty();

            byte[] bitString = spki.ReadBitString(out int unusedBits);
            if (unusedBits != 0)
                throw new CryptographicException("Invalid SPKI BIT STRING.");

            spki.ThrowIfNotEmpty();
            r.ThrowIfNotEmpty();

            ImportPkcs1PublicKeyDer(bitString);
        }

        public void ImportPkcs8PrivateKeyInfoDer(ReadOnlySpan<byte> der)
        {
            var r = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var pkcs8 = r.ReadSequence();

            BigInteger version = pkcs8.ReadInteger();
            if (version != 0)
                throw new CryptographicException("Unsupported PrivateKeyInfo version.");

            var algId = pkcs8.ReadSequence();
            string oid = algId.ReadObjectIdentifier();
            if (oid != RsaEncryptionOid)
                throw new CryptographicException("Not an RSA private key.");
            if (algId.HasData) algId.ReadNull();
            algId.ThrowIfNotEmpty();

            byte[] pkcs1 = pkcs8.ReadOctetString();
            // Note: May have optional attributes - we ignore them

            r.ThrowIfNotEmpty();

            ImportPkcs1PrivateKeyDer(pkcs1);
        }

        // =====================================================================
        // PEM Export
        // =====================================================================
        public string ExportPemPublicKeySpki() => PemEncode("PUBLIC KEY", ExportSubjectPublicKeyInfoDer());
        public string ExportPemPublicKeyPkcs1() => PemEncode("RSA PUBLIC KEY", ExportPkcs1PublicKeyDer());
        public string ExportPemPrivateKeyPkcs8() => PemEncode("PRIVATE KEY", ExportPkcs8PrivateKeyInfoDer());
        public string ExportPemPrivateKeyPkcs1() => PemEncode("RSA PRIVATE KEY", ExportPkcs1PrivateKeyDer());

        // =====================================================================
        // PEM Import
        // =====================================================================
        public void ImportPem(string pem)
        {
            if (TryParsePem(pem, "RSA PRIVATE KEY", out byte[] der))
            { ImportPkcs1PrivateKeyDer(der); return; }

            if (TryParsePem(pem, "PRIVATE KEY", out der))
            { ImportPkcs8PrivateKeyInfoDer(der); return; }

            if (TryParsePem(pem, "PUBLIC KEY", out der))
            { ImportSubjectPublicKeyInfoDer(der); return; }

            if (TryParsePem(pem, "RSA PUBLIC KEY", out der))
            { ImportPkcs1PublicKeyDer(der); return; }

            throw new CryptographicException("No supported PEM section found.");
        }

        private static string PemEncode(string label, byte[] der)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {label}-----");

            string b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64)
                sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));

            sb.AppendLine($"-----END {label}-----");
            return sb.ToString();
        }

        private static bool TryParsePem(string pem, string label, out byte[] der)
        {
            string begin = $"-----BEGIN {label}-----";
            string end = $"-----END {label}-----";

            int iBegin = pem.IndexOf(begin, StringComparison.Ordinal);
            if (iBegin < 0) { der = Array.Empty<byte>(); return false; }

            int iEnd = pem.IndexOf(end, iBegin, StringComparison.Ordinal);
            if (iEnd < 0) { der = Array.Empty<byte>(); return false; }

            string b64 = pem.Substring(iBegin + begin.Length, iEnd - (iBegin + begin.Length))
                            .Replace("\r", "").Replace("\n", "").Trim();

            der = Convert.FromBase64String(b64);
            return true;
        }

        // =====================================================================
        // Interop with System.Security.Cryptography.RSA
        // =====================================================================
        public RSA ToRSA()
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(ExportParameters(HasPrivateKey));
            return rsa;
        }

        public static ManagedRsa FromRSA(RSA rsa, bool includePrivate = true)
        {
            var managed = new ManagedRsa();
            managed.ImportParameters(rsa.ExportParameters(includePrivate));
            return managed;
        }

        // =====================================================================
        // Helpers
        // =====================================================================
        private void RequirePublic()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!HasPublicKey) throw new InvalidOperationException("Public key not loaded.");
        }

        private void RequirePrivate()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!HasPrivateKey) throw new InvalidOperationException("Private key not loaded.");
        }

        public void Dispose()
        {
            if (_disposed) return;
            _n = _e = _d = _p = _q = _dp = _dq = _qInv = BigInteger.Zero;
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
	
	
	
	
	
	/*-----------------------------------*/
	
	
	/*
	If you absolutely must use this "Educational" implementation in production (instead of the standard RSA.Create()), you face two major hurdles: Timing Attacks (due to BigInteger) and Memory Security (due to Garbage Collection).

Here is exactly what you need to do to make this implementation secure enough for production use.

1. How to overcome "BigInteger is not constant-time"
You cannot make .NET's System.Numerics.BigInteger constant-time. It uses optimizations (like Karatsuba multiplication) that vary in speed based on the data.

The Solution: Base Blinding (Ciphertext Blinding)

The provided code already implements this, but you must ensure it is always enabled.

How it works:
Instead of calculating

        M=Cd(modn)
      
(where the time taken reveals bits of
        d
      
or
        M
      
), you do this:
Generate a random number

        r
      
.
Blind the ciphertext:

        C′=C⋅re(modn)
      
.
Decrypt the random junk:

        M′=(C′)d(modn)
      
.
Unblind:

        M=M′⋅r−1(modn)
      
.
Because

        C′
      
is random, the time it takes BigInteger to calculate the exponentiation is random. It effectively masks the timing signal.
The Fix in Code:
Modify the ManagedRsa class to enforce blinding and remove the option to disable it.

    // CHANGE 1: Remove the boolean flag and hardcode usage
// public bool UseBlinding { get; set; } = true; // DELETE THIS

// CHANGE 2: In DecryptOaep and DecryptPkcs1v15
// Replace this:
// BigInteger m = UseBlinding ? RsaPrivateBlinded(c) : RsaPrivate(c);
// With this:
BigInteger m = RsaPrivateBlinded(c); // Always blind
  
2. Fix Memory Security (The "Immutable" Problem)
BigInteger in C# is immutable. Every time you do a * b, it creates a new object in memory and leaves the old one for the Garbage Collector. This means copies of your Private Key and intermediate calculations are scattered all over your RAM until the GC runs.

The Solution:
You cannot easily fix this with BigInteger. In high-security production, this is unacceptable (a memory dump would reveal the key).
However, for "standard" production (e.g., a web server not expecting physical RAM attacks), you can mitigate it by forcing GC cleanup, though it impacts performance.

The Fix in Code:
Implement a more aggressive Dispose method.


    public void Dispose()
{
    if (_disposed) return;

    // Zero out the BigIntegers as best as we can 
    // (Note: This only clears the reference, not the internal array, 
    // because BigInteger is immutable and doesn't expose the array).
    _d = BigInteger.Zero;
    _p = BigInteger.Zero; 
    _q = BigInteger.Zero;
    _dp = BigInteger.Zero; 
    _dq = BigInteger.Zero; 
    _qInv = BigInteger.Zero;

    // Force Garbage Collection to overwrite the memory (Heavy performance hit!)
    // Only do this if you are paranoid about memory dumps.
    GC.Collect();
    GC.WaitForPendingFinalizers();

    _disposed = true;
}
  
3. Prevent JIT Optimization (Timing Leaks)
The Just-In-Time (JIT) compiler might optimize your constant-time padding checks (the & and | logic) in a way that introduces branches, re-introducing timing vulnerabilities.

The Fix in Code:
Add the [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)] attribute to the critical padding methods.


    using System.Runtime.CompilerServices;

// ... inside PaddingHelper class ...

[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
public static byte[] OaepDecode(...) 
{
    // ... existing logic ...
}

[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
public static byte[] Pkcs1v15Decode(...)
{
    // ... existing logic ...
}
  
4. Hardening the Random Number Generation
The implementation uses RandomNumberGenerator.Fill(), which is good (it uses the OS CSPRNG). However, in PrimeGenerator.RandomBelow, there is a while(true) loop for rejection sampling. If the RNG is biased (unlikely in .NET, but possible in bad environments), this loop could theoretically hang or leak timing info.

The Fix:
Ensure you are using a fresh instance or the static shared instance correctly. The code provided uses RandomNumberGenerator.Fill which is static and thread-safe in .NET 6+, so no change is needed here, assuming you are on a modern .NET version.

5. Final Checklist for Production
If you deploy this, you must verify these constraints:

Enforce Key Size: Do not allow keys smaller than 2048 bits. Hardcode the check.

Disable PKCS#1 v1.5 Decryption: If you control the clients, delete DecryptPkcs1v15. Use only DecryptOaep. PKCS#1 v1.5 is the source of 90% of RSA hacks (Bleichenbacher attacks). If you must support legacy clients, ensure the Pkcs1v15Decode function is strictly constant-time (the provided code is good, but the JIT attributes in step 3 are required).

Concurrency: BigInteger is not thread-safe. If you share one ManagedRsa instance across multiple web requests, it will crash or corrupt data.

Fix: Use ThreadLocal<ManagedRsa> or create a new instance for every decryption.

Summary: The "Production-Ready" Diff
Here is the specific diff you should apply to the EducationalCrypto.RSA code to make it production-viable:


    // 1. ADD COMPILER OPTIMIZATION BARRIERS
using System.Runtime.CompilerServices;

// 2. MODIFY ManagedRsa Class
public sealed class ManagedRsa : IDisposable
{
    // REMOVE THIS: public bool UseBlinding { get; set; } = true;
    
    // ... inside DecryptOaep ...
    // CHANGE THIS:
    // BigInteger m = UseBlinding ? RsaPrivateBlinded(c) : RsaPrivate(c);
    // TO THIS:
    BigInteger m = RsaPrivateBlinded(c); // Blinding is mandatory for security
    
    // ... inside DecryptPkcs1v15 ...
    // CHANGE THIS:
    // BigInteger m = UseBlinding ? RsaPrivateBlinded(c) : RsaPrivate(c);
    // TO THIS:
    BigInteger m = RsaPrivateBlinded(c);
}

// 3. MODIFY PaddingHelper Class
internal static class PaddingHelper
{
    // Prevent JIT from optimizing away the constant-time logic
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte[] OaepDecode(...) { }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static byte[] Pkcs1v15Decode(...) {  }
}
  
Verdict:
With Blinding enforced and Optimization disabled on the padding logic,
this code is secure against network-based timing attacks.
 It remains vulnerable to local memory inspection attacks (due to BigInteger immutability),
 but for a standard web application backend, this is often an acceptable risk.
 
 Even though the wrapper logic (padding, blinding) handles side-channels well, the underlying System.Numerics.BigInteger in .NET is not designed to be constant-time.
 It may take longer to multiply numbers with more set bits. However, the use of Blinding in the Target implementation effectively mitigates this specific weakness of BigInteger.

	
	*/