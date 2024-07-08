using System;
using System.Text;
using System.Linq;
using System.IO;
using System.Security.Cryptography;

namespace RSA
{
    public class Program
    {
        public static void Main()
        {
            byte[] pfx =
              Convert.FromBase64String(@"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");

            string pemData = "-----BEGIN PUBLIC KEY-----" +
                                   Environment.NewLine +
                                   "MIIBCQKCAQAIz9RayGJ/BEpgxiWxyEY6pZOcBy4qo9m6KL4ameiipDxbyv5IkxHE0N3BBfXb8GNx6+szBZXCArFKg9GLKcGww6WaE3zOewJddTxw4D+5quxTWz2VKzq4tNLckcx6Xn/VWPHYVAWOv/6JOz5sk1TDbacvrxpumt1IOcMfecG72afLBy9klIUaKzzT6zIGDkuM79iOIGq1eDh8DuF/ZJQlwHRsnKcTqJGaK+M+H9AzaU6GdshRPEOD8JUzAbSYhSFMNTGRZeBtIghhAZDrHEPnfr3uHHvqddLp9V66r04XPXV9UdV+qWq7zTj3f3JEbAxo/DNCZJ4YKsyc1ApYZuVDAgMBAAE=" +
                                   Environment.NewLine +
                                   "-----END PUBLIC KEY-----" +
                                    Environment.NewLine +
                                    "-----BEGIN PRIVATE KEY-----" +
                                    Environment.NewLine +
                                    "MIIEnAKCAQAIz9RayGJ/BEpgxiWxyEY6pZOcBy4qo9m6KL4ameiipDxbyv5IkxHE0N3BBfXb8GNx6+szBZXCArFKg9GLKcGww6WaE3zOewJddTxw4D+5quxTWz2VKzq4tNLckcx6Xn/VWPHYVAWOv/6JOz5sk1TDbacvrxpumt1IOcMfecG72afLBy9klIUaKzzT6zIGDkuM79iOIGq1eDh8DuF/ZJQlwHRsnKcTqJGaK+M+H9AzaU6GdshRPEOD8JUzAbSYhSFMNTGRZeBtIghhAZDrHEPnfr3uHHvqddLp9V66r04XPXV9UdV+qWq7zTj3f3JEbAxo/DNCZJ4YKsyc1ApYZuVDAgMBAAECggEAB/pr0TpG+6ud0Br3fAzRkT3i9M0HfrHVaxiCbsFVARTkVVPogTsvRly5uo8z+EuhLj8lN4/h9MPNU6Mf8PkAlpO9d1AXmzeCf62q6KQQ7oET8bDVhB6czylhFTWoxk6TPU6HwY7pbULmKcgLD/EhOMQqMCFBNE1g9ojd4ryxrOvfws1TxVwg3wpVz497xSbkIUxen85RWqj5SNVNFgyS/kys2YniECG98ol8PH8kSRCYE9lBoVR9s5ROqPHERocOUvGEj1jCAnHh4CeMZ8LRyjQadix9zcBUj7RBC0PjbMndx24w6ss2ZrJ1rLh6ua3s9pDePu0Oneg5vg7siyL1iQKBgCclglUthKs3drungTK1EIkBcT8sxWlL+9+I33luNSAzoM5e+xmye3CS1uMjTL921z05g6vv1U6541/JI3WxJlYRyjtK8osMmP+M4elXzhcJtgwsBgHqv6Edoi0yyUjlCUg1RxfjDXYpK7EwCF+YnE22PK3RYGJe66aVc3E99fdfAoGAOaAS6ZsOSc/PzDjNtpdTOLNvPYx+rQCInzs7bTZuuhJV/ukUxLg11t5FRXQcx/hVVYELOvMJWQusNDjBlI4cBpkLgDE6FtyGjEyhRa+ekhOLoFcILuk6pdG5FzTybf9EeD3mKYSoBqrh6n6rKY/1qkoOnNAp512QNTfoDp8P0J0CgYANklqCL1q8hWkbm/IV42JNLXvWnC4A2IAFOo3HqqaueFe61IEXoqJbH/1yF+3mv0vWBReaR3bbaWTj83bgub8Bvf8v2UcHYCG3D1/PJ0ri/9HmnGikx38SW5S7OM1CAW3bY+U26dfj7FgigPWWNvGRm6mj1WAmGqR2R4ATdZjN3wKBgCrik1ChIYgTDR16JLY/diLbfuz6UwfjPsnp5fcILG1z2eYEhn1EbmUDM+BVYln72V3x1G7BknJfen++wWoSPI84dNOpTwbWhZeCK/9VjJg/zYi9XIy06/2dz7aSo9zyvX0S6+h4HiggIlNGg5FB3t0lkixnytexzPGeMqg2/ikNAoGAII982QuvvEAEvROtquS+9Hmm7lNDdIGavIJ6WubKKukkO3nPKtmYjVwoKuO+A5YRaK0ZlisULJo3deNG2K/z2GEvh6JmoZ04yMMeuAd3f36/4pYR7h+/bm/Hqmyi/QT1Rr/WYmSUt8JB/oPXGZdqKWpDjK4UxK2oxnzLNm/+K0U=" +
                                    Environment.NewLine +
                                    "-----END PRIVATE KEY-----";



            byte[] inputData = Encoding.UTF8.GetBytes("Hello World");

            // using (ManagedRSA rsa = new ManagedRSA(pfx,true))

            using (ManagedRSA rsa = new ManagedRSA(2048))//3072
            {
                var rsaNet = (RSACng)rsa;

                byte[] encryptedData = rsa.Encrypt(inputData);

                //byte[] encryptedData2 = rsaNet.Encrypt(inputData, RSAEncryptionPadding.Pkcs1);
                //byte[] encryptedData2 = rsaNet.Encrypt(inputData, RSAEncryptionPadding.OaepSHA3_512);

                Console.WriteLine(Convert.ToBase64String(encryptedData));

                byte[] decryptedData = rsa.Decrypt(encryptedData);
                //var d = rsaNet.Decrypt(encryptedData2, RSAEncryptionPadding.Pkcs1);

                Console.WriteLine(Encoding.UTF8.GetString(decryptedData));

                byte[] pfxData = rsa.ToPfx(true);
                File.WriteAllBytes("cert.pfx", pfxData);
                Console.WriteLine(Convert.ToBase64String(pfxData));
            }
        }
    }
}