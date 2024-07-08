# ManagedRSA
managed c# modern implementation of RSA (with CRT decrypt , OAEP-mgf1/PKCS#1 v1.5 pad, pkcs12 Pss pfx cert, miller-rabin 50 prime gen)

impl based on BigInteger(little endian,rsa is big endian) , Chinese Remainder Theorem(more performant decrypt) ,cryptographic RandomNumberGenerator

pkcs12 impl based on X509Certificate2,RSACng

ExtendedGCD has recursive impl and iterative impl,

_e/_publicExponent coprime is 0x10001(65537)

also has , pem cert support , Montgomery exponentiation support for perf, blinding protection against side channel attacks,
FixedTimeEquals against timing attacks

keySize is 2048 by default for perf, but 3072 or above is recommended

todo: 

OAEP-SHA3-512 pad , instead of sha2

GetBitLength() might need fix to be more accurate

remove default Password from key managment , get as parameter(secure string maybe)


fixes todo:
The use of BigInteger.ModPow for core RSA operations is not constant-time, 
which could lead to timing attacks. Consider using a constant-time modular exponentiation implementation.(like Montgomery exponentiation)

The PKCS#1 v1.5 padding implementation may be vulnerable to padding oracle attacks. It's generally recommended to use OAEP padding instead.

The OAEP padding implementation seems incomplete and may not be correct.

The PEM import/export functions have issues and may not correctly handle all cases.

The GenerateBlindingFactor method doesn't ensure that the blinding factor is coprime to the modulus.

The prime generation method (GeneratePrimeNumber) could be optimized to use sieving for better performance.
The idea is to use a sieve to quickly eliminate numbers that are divisible by small primes before applying the more expensive Miller-Rabin test.

