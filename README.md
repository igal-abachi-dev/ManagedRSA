# ManagedRSA
managed c# implementation of RSA (with CRT decrypt , OAEP-mgf1/PKCS#1 v1.5 pad, pkcs12 Pss pfx cert, miller-rabin 50 prime gen)

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
