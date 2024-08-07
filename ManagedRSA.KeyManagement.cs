using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSA;

public partial class ManagedRSA
{
    private const string Password = "HelloWorld!";

    /// <summary>
    /// Load public and private keys from PKCS#12 (PFX) data.
    /// </summary>
    public void FromPfx(byte[] pfxData, bool isPrivateKey = false)
    {
        var cert = new X509Certificate2(pfxData, Password, X509KeyStorageFlags.Exportable);
        var privKey = cert.GetRSAPrivateKey() as RSACng;
        if (privKey == null)
        {
            throw new InvalidOperationException("Private key not found in the certificate.");
        }

        using (privKey)
        {
            RSAParameters rsaParameters;
            if (isPrivateKey)
            {
                try{
                    rsaParameters = privKey.ExportParameters(true);
                }
            catch{
                var bytes = privKey.ExportEncryptedPkcs8PrivateKey(
                    Password,
                    new PbeParameters(
                        PbeEncryptionAlgorithm.Aes256Cbc,
                        HashAlgorithmName.SHA256,
                        iterationCount: 100_000));

                using (RSACng rsa = new RSACng())
                {
                    rsa.ImportEncryptedPkcs8PrivateKey(Password, bytes, out _);
                    rsaParameters = rsa.ExportParameters(true);
                }
              }
            }
            else
            {
                rsaParameters = privKey.ExportParameters(false);
            }

            _modulus = new BigInteger(rsaParameters.Modulus.Reverse().ToArray());
            _publicKey = new BigInteger(rsaParameters.Exponent.Reverse().ToArray());
            _isPublicKeyLoaded = true;

            if (isPrivateKey)
            {
                _privateKey = new BigInteger(rsaParameters.D.Reverse().ToArray());
                _p = new BigInteger(rsaParameters.P.Reverse().ToArray());
                _q = new BigInteger(rsaParameters.Q.Reverse().ToArray());
                _dp = new BigInteger(rsaParameters.DP.Reverse().ToArray());
                _dq = new BigInteger(rsaParameters.DQ.Reverse().ToArray());
                _qInv = new BigInteger(rsaParameters.InverseQ.Reverse().ToArray());
                _isPrivateKeyLoaded = true;
            }
        }
    }

    /// <summary>
    /// Exports the key as a PKCS#12 (PFX) byte array.
    /// </summary>
    public byte[] ToPfx(bool includePrivateParameters)
    {
        using (var rsa = ToRSA(this, includePrivateParameters))
        {
            var p = rsa.ExportParameters(true);
            var certRequest = new CertificateRequest("CN=ManagedRSA", rsa,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pss);// Use Pkcs1 for compatibility? less secure
            var cert = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(2));

            // If we're not including private parameters, export as a public-key only PFX?
            //if (!includePrivateParameters)
            //{
            //    return cert.Export(X509ContentType.Cert);
            //}

            return cert.Export(X509ContentType.Pfx, Password);
        }
    }

//pem load/save doesn't work yet
    /// <summary>
    /// Loads public and private keys from PEM strings.
    /// </summary>
    public void FromPemString(string pemString)
    {
        string publicKeyPem = GetPemSection(pemString, "PUBLIC KEY");
        string privateKeyPem = GetPemSection(pemString, "PRIVATE KEY");

        if (publicKeyPem == null)
        {
            throw new Exception("Public key not found in the provided PEM string.");
        }

        // Process public key
        var publicKeyBytes = Convert.FromBase64String(publicKeyPem);
        using (var ms = new MemoryStream(publicKeyBytes))
        using (var reader = new BinaryReader(ms))
        {
            int twobytes = reader.ReadUInt16();
            if (twobytes == 0x8130)
                reader.ReadByte();
            else if (twobytes == 0x8230)
                reader.ReadInt16();
            else
                throw new Exception("Invalid key format");

            reader.ReadByte(); // Skip version

            _modulus = ReadAsn1Integer(reader);
            _publicKey = ReadAsn1Integer(reader);
            _isPublicKeyLoaded = true;
        }

        // Process private key if present
        if (privateKeyPem != null)
        {
            var privateKeyBytes = Convert.FromBase64String(privateKeyPem);
            using (var ms = new MemoryStream(privateKeyBytes))
            using (var reader = new BinaryReader(ms))
            {
                if (reader.ReadByte() != 0x30)
                    throw new Exception("Invalid key format");
                reader.ReadByte(); // Skip the length byte

                if (reader.ReadByte() != 0x02)
                    throw new Exception("Invalid key version");

                _modulus = ReadAsn1Integer(reader);
                _publicKey = ReadAsn1Integer(reader);
                _isPublicKeyLoaded = true;

                _privateKey = ReadAsn1Integer(reader);
                _p = ReadAsn1Integer(reader);
                _q = ReadAsn1Integer(reader);
                _dp = ReadAsn1Integer(reader);
                _dq = ReadAsn1Integer(reader);
                _qInv = ReadAsn1Integer(reader);
                _isPrivateKeyLoaded = true;
            }
        }

    }
    private string GetPemSection(string pemString, string sectionName)
    {
        string header = $"-----BEGIN {sectionName}-----";
        string footer = $"-----END {sectionName}-----";

        int start = pemString.IndexOf(header, StringComparison.Ordinal);
        if (start < 0) return null;

        start += header.Length;
        int end = pemString.IndexOf(footer, start, StringComparison.Ordinal);
        if (end < 0) return null;

        return pemString.Substring(start, end - start)
            .Replace("\n", "")
            .Replace("\r", "").Trim();
    }
    private BigInteger ReadAsn1Integer(BinaryReader reader)
    {
        byte tag = reader.ReadByte();//130 why , 130 is the length

        int length;
        if (tag != 0x02)
            length = tag;//throw new Exception($"Invalid key format. Expected 0x02 but got 0x{tag:X2}");
        else
            length = reader.ReadByte();
        if (length == 0x81)
        {
            length = reader.ReadByte();
        }
        else if (length == 0x82)
        {
            length = 256 * reader.ReadByte() + reader.ReadByte();
        }
        else if (length >= 0x80)
        {
            throw new Exception("Unsupported ASN.1 length format.");
        }

        var integerBytes = reader.ReadBytes(length);
        return new BigInteger(integerBytes.Reverse().ToArray());
    }

    /// <summary>
    /// Exports the key as a PEM string.
    /// </summary>
    public string ToPemString(bool includePrivateParameters)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(ExportKey(false)));
        builder.AppendLine("-----END PUBLIC KEY-----");

        if (includePrivateParameters && _isPrivateKeyLoaded)
        {
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(ExportKey(true)));
            builder.AppendLine("-----END PRIVATE KEY-----");
        }

        return builder.ToString();
    }

    /// <summary>
    /// Exports the key data.
    /// </summary>
    private byte[] ExportKey(bool includePrivateParameters)
    {
        using (var ms = new MemoryStream())
        using (var writer = new BinaryWriter(ms))
        {
            writer.Write((byte)0x30); // ASN.1 SEQUENCE
            using (var innerStream = new MemoryStream())
            using (var innerWriter = new BinaryWriter(innerStream))
            {
                WriteAsn1Integer(innerWriter, _modulus);
                WriteAsn1Integer(innerWriter, _publicKey);

                if (includePrivateParameters && _isPrivateKeyLoaded)//PKCS#8 format
                {
                    WriteAsn1Integer(innerWriter, _privateKey);
                    WriteAsn1Integer(innerWriter, _p);
                    WriteAsn1Integer(innerWriter, _q);
                    WriteAsn1Integer(innerWriter, _dp);
                    WriteAsn1Integer(innerWriter, _dq);
                    WriteAsn1Integer(innerWriter, _qInv);
                }

                var length = (int)innerStream.Length;
                if (length > 255)
                {
                    writer.Write((byte)0x82);
                    writer.Write((byte)(length >> 8));
                    writer.Write((byte)length);
                }
                else
                {
                    writer.Write((byte)0x81);
                    writer.Write((byte)length);
                }

                innerStream.WriteTo(ms);
            }

            return ms.ToArray();
        }
    }
    private void WriteAsn1Integer(BinaryWriter writer, BigInteger value)
    {
        // Get the bytes in big-endian format
        var bytes = value.ToByteArray().Reverse().ToArray();

        // Ensure the number is positive by adding a leading zero if the most significant bit is set
        if (bytes[0] >= 0x80)
        {
            var newBytes = new byte[bytes.Length + 1];
            Array.Copy(bytes, 0, newBytes, 1, bytes.Length);
            bytes = newBytes;
        }

        writer.Write((byte)0x02); // ASN.1 INTEGER

        // Write the length
        if (bytes.Length < 128)
        {
            writer.Write((byte)bytes.Length);
        }
        else if (bytes.Length < 256)
        {
            writer.Write((byte)0x81);
            writer.Write((byte)bytes.Length);
        }
        else
        {
            writer.Write((byte)0x82);
            writer.Write((byte)(bytes.Length >> 8));
            writer.Write((byte)(bytes.Length & 0xFF));
        }

        // Write the bytes
        writer.Write(bytes);
    }

}
