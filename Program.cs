using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace SymmetricEncryptionStandardExampleAES
{



    public class SymmetricEncryptionStandardExampleAES
    {
        static string key_1 = "test";
        
        public static string EncryptWithAESGCM(string plainText, string Key)
        {
            string key = ComputeSha256Hash(Key);
            Aes aesAlg = Aes.Create();
            byte[] keyBytes = Convert.FromBase64String(key);
            aesAlg.Key = keyBytes.Take(32).ToArray();
            aesAlg.Mode = CipherMode.ECB; // Use CBC mode for AES
           // aesAlg.Padding = PaddingMode.PKCS7; // Use PKCS7 padding

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(ConvertBase64ToByteArray(key), aesAlg.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                memoryStream.Write(aesAlg.IV, 0, aesAlg.IV.Length); // Write IV to the beginning of the stream
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);
                }
                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }
        public static string DecryptWithAESGCM(string cipherText, string Key)
        {
            string key = ComputeSha256Hash(Key);
            byte[] cipherTextBytes =ConvertBase64ToByteArray(cipherText);
            string resultcipher = hexstring(cipherTextBytes);
            byte[] keyBytes = ConvertBase64ToByteArray(key);
            Aes aesAlg = Aes.Create();
           //aesAlg.Key = keyBytes.Take(32).ToArray();
            aesAlg.Mode = CipherMode.ECB; 
            aesAlg.Padding = PaddingMode.PKCS7; // Use PKCS7 padding

            byte[] iv = new byte[16]; // IV size based on block size
            Array.Copy(cipherTextBytes, iv, iv.Length); // Extract IV from the beginning of the ciphertext

            aesAlg.IV = iv;

            using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes, iv.Length, cipherTextBytes.Length - iv.Length))
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader streamReader = new StreamReader(cryptoStream))
            {
                return streamReader.ReadToEnd();
            }
        }
        private static byte[] ConvertBase64ToByteArray(string arrayString)
        {
            byte[] byteArray = Convert.FromBase64String(arrayString);
            return byteArray;
        }
        //    public static string Encrypt(string plaintext, string key)
        //    {
        //        using (Aes AesAlgo = Aes.Create())
        //        {
        //            AesAlgo.KeySize = 256;
        //            byte[] keyByte = Encoding.UTF8.GetBytes(key);
        //            AesAlgo.Key = keyByte.Take(32).ToArray();
        //            AesAlgo.GenerateIV();

        //            using (ICryptoTransform encrypto = AesAlgo.CreateEncryptor(AesAlgo.Key, AesAlgo.IV))

        //            using (MemoryStream msencrypt = new MemoryStream())
        //            {
        //                // write the IV in the begining of the memory stream 
        //                msencrypt.Write(AesAlgo.IV, 0, AesAlgo.IV.Length);

        //                using (CryptoStream csencryptor = new CryptoStream(msencrypt, encrypto, CryptoStreamMode.Write))

        //                using (StreamWriter Encsr = new StreamWriter(csencryptor))
        //                {
        //                    Encsr.Write(plaintext);
        //                }
        //                byte[] encrytpedbytes = msencrypt.ToArray();
        //                return Convert.ToBase64String(encrytpedbytes);

        //            }



        //        }
        //    }
        //    public static string Decrypt(string ciphertext, string key)
        //    {
        //        byte[] cipherbytes = Convert.FromBase64String(ciphertext);

        //        using (Aes algo = Aes.Create())
        //        {
        //            algo.KeySize = 256;
        //            byte[] keyByte = Encoding.UTF8.GetBytes(key);
        //            algo.Key =keyByte.Take(32).ToArray();
        //            byte[] iv = new byte[algo.BlockSize / 8];
        //            // extract iv from the cipher text 
        //            Array.Copy(cipherbytes, 0, iv, 0, iv.Length);
        //            algo.IV = iv;
        //            using (ICryptoTransform decryptor = algo.CreateDecryptor(algo.Key, algo.IV))
        //            using (MemoryStream msDecrypt = new MemoryStream(cipherbytes, iv.Length, cipherbytes.Length - iv.Length))
        //            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
        //            {
        //                return srDecrypt.ReadToEnd();
        //            }
        //        }
        //    }


        //public static string Encrypt(string plaintext)
        //{
        //    using (Aes aesalg = Aes.Create())
        //    {
        //        aesalg.KeySize = 256;
        //        aesalg.Mode = CipherMode.CBC;
        //        aesalg.Padding = PaddingMode.PKCS7;
        //        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        //        aesalg.Key = keyBytes.Take(32).ToArray();
        //        ICryptoTransform encrypto = aesalg.CreateEncryptor(aesalg.Key, aesalg.IV);

        //        using (MemoryStream memoryStream = new MemoryStream())
        //        {
        //            memoryStream.Write(aesalg.IV, 0, aesalg.IV.Length); // Write IV to the beginning of the stream
        //            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encrypto, CryptoStreamMode.Write))
        //            using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
        //            {
        //                streamWriter.Write(plaintext);
        //            }
        //            return Convert.ToBase64String(memoryStream.ToArray());
        //        }

        //    }

        //}

        //public static string Decrypt(string ciphertext)
        //{
        //    byte[] cipherBytes = Convert.FromBase64String(ciphertext);
        //    string cipher = hexstring(cipherBytes);

        //    using (Aes aesalgo = Aes.Create())
        //    {
        //        //aesalgo.KeySize = 256;
        //        aesalgo.Mode = CipherMode.CBC;
        //        aesalgo.Padding = PaddingMode.PKCS7;
        //        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        //        aesalgo.Key = keyBytes.Take(32).ToArray();
        //        byte[] iv = new byte[aesalgo.BlockSize / 8];
        //        Array.Copy(cipherBytes, iv, iv.Length);
        //        aesalgo.IV = iv;
        //        using (MemoryStream memoryStream = new MemoryStream(cipherBytes, iv.Length, cipherBytes.Length - iv.Length))
        //        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesalgo.CreateDecryptor(), CryptoStreamMode.Read))
        //        using (StreamReader streamReader = new StreamReader(cryptoStream))
        //        {
        //            return streamReader.ReadToEnd();
        //        }
        //    }


        //}
        public static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256 instance
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // Compute the hash as a byte array
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                return Convert.ToBase64String(bytes);
            }

        }
        static string hexstring(byte[] array)
        {
            string hexstring = Convert.ToBase64String(array);
            return hexstring;
        }
    }




        public class SymmetricEncryptionStandardExampleAESGCM
        {
            public static byte[] Encrypt(string plaintext, byte[] key, byte[] nonce)
            {
                using (AesGcm aesGcm = new AesGcm(key))
                {
                    byte[] ciphertext = new byte[plaintext.Length];
                    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                    byte[] textByte = Encoding.UTF8.GetBytes(plaintext);
                    aesGcm.Encrypt(nonce, textByte, ciphertext, tag);
                    byte[] encryptedmessage = new byte[nonce.Length + ciphertext.Length + tag.Length];
                    Buffer.BlockCopy(nonce, 0, encryptedmessage, 0, nonce.Length);
                    Buffer.BlockCopy(ciphertext, 0, encryptedmessage, nonce.Length, ciphertext.Length);
                    Buffer.BlockCopy(tag, 0, encryptedmessage, nonce.Length + ciphertext.Length, tag.Length);
                    return encryptedmessage;

                }
            }
            public static string Decrypt(byte[] encryptedmessage, byte[] key)
            {
                byte[] nonce = new byte[12];
                byte[] ciphertext = new byte[encryptedmessage.Length - 12 - 16];
                byte[] tag = new byte[16];
                // extract encrypted message from nonce ,chiphertext,tag
                Buffer.BlockCopy(encryptedmessage, 0, nonce, 0, nonce.Length);
                Buffer.BlockCopy(encryptedmessage, nonce.Length, ciphertext, 0, ciphertext.Length);
                Buffer.BlockCopy(encryptedmessage, nonce.Length + ciphertext.Length, tag, 0, tag.Length);
                var x = ciphertext.Length;
                using (AesGcm aesgcm = new AesGcm(key))
                {
                    byte[] plaintext = new byte[ciphertext.Length];
                    aesgcm.Decrypt(nonce, ciphertext, tag, plaintext);
                    return Encoding.UTF8.GetString(plaintext);
                }

            }

        }
        //Asymettric examples 
        public class RSADEMO()
        {
            public static void RSAMethod(string plaintext)
            {
                try
                {
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        Console.WriteLine("RSA public-key" + "\n" + rsa.ToXmlString(false));
                        byte[] plainText_Bytes = Encoding.UTF8.GetBytes(plaintext);
                        byte[] rsaEncryptedmsg = rsa.Encrypt(plainText_Bytes, false);
                        Console.WriteLine("welcome to RSA your encrypted message:\n");
                        Console.WriteLine(Convert.ToBase64String(rsaEncryptedmsg));
                        byte[] rsaDecryptmsg = rsa.Decrypt(rsaEncryptedmsg, false);
                        Console.WriteLine("RSA Decrypted message: " + Convert.ToBase64String(rsaDecryptmsg));
                    }

                }
                catch (Exception)
                {

                    throw;
                }
            }
        }
        public class SHACompute
        {
            public static void SHAComputeMethod(string plaintext)
            {
                byte[] plainbytes = Encoding.UTF8.GetBytes(plaintext);
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] computehash = sha256.ComputeHash(plainbytes);

                    //Console.WriteLine("hash value: " + computehash);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < computehash.Length; i++)
                    {
                        sb.Append(computehash[i].ToString("x2"));
                    }
                    Console.WriteLine(sb.ToString());
                }
            }

        }
        public class HmacShaCompute
        {
            public static void HmaShaComputeMethod(string plaintext, string key)
            {
                byte[] Keybytes = Encoding.UTF8.GetBytes(key);
                byte[] plaintextbytes = Encoding.UTF8.GetBytes(plaintext);
                using (HMACSHA256 Hmac256 = new HMACSHA256())
                {
                    byte[] hashbytes = Hmac256.ComputeHash(plaintextbytes);
                    StringBuilder sb = new StringBuilder();
                    Console.WriteLine(hashbytes.ToString());

                }

            }

        }
        public class Program
        {
            public static void Main(string[] args)
            {

                //Console.WriteLine("Hello, World!");
                string plaintext = "Hello Aes-GCM Successful implementation";
                //string key = "0123456789ABCDEF0123456789ABCDEF";
                string key = "test";
                Console.WriteLine(plaintext);
                Console.WriteLine("please select your encrption alogrithm");
                Console.WriteLine("A.PlainAES" + "\n" + "B.AESGCM" + "\n" + "C.RSA" + "\n" + "D.SHA256 Generate hash" + "\n" + "E.HMACSHA");
                string readkey = Console.ReadLine();
                switch (readkey)
                {
                    case "A":
                        Plain_AES_trigger(plaintext, key);
                        break;
                    case "B":
                        AES_GCM_trigger(plaintext);
                        break;
                    case "C":
                        RSA_trigger(plaintext);
                        break;
                    case "D":
                        SHA256_trigger(plaintext);
                        break;
                    case "E":

                    default:
                        Console.WriteLine("Invalid input. Please enter a valid option (a, b, c, d).");
                        break;


                }


            }

            public static void Plain_AES_trigger(string plaintext, string key)
            {
                Console.WriteLine("welcome to plainAES heres your output:");
            try
            {

                //string Encrypt = SymmetricEncryptionStandardExampleAES.Encrypt(plaintext);
                //Console.WriteLine("encrypted text: " + Encrypt);
                string Decrypt = SymmetricEncryptionStandardExampleAES.DecryptWithAESGCM("p3p9ZnnrPuI8m7lj72IUM9JMsFwG7Z8kx1XQtI6gcHIoY6JLEjtUFMHfy9nY1guas3o5TkctuW6++DI=", "test");

                Console.WriteLine("Decrypted text: " + Decrypt);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error : {ex.Message}");

                }
            }
            public static void AES_GCM_trigger(string plaintext)
            {
                Console.WriteLine("welcome to AESGCM heres your output:");
            //byte[] key = GenerateAES256Key();
            string hashkey = 
            byte[] key = GenerateKeyBytes("test");

                byte[] nonce = GenerateRandomNonce();
                Console.WriteLine("Key: " + Convert.ToBase64String(key) + "\n" + "nonce: " + Convert.ToBase64String(nonce));
                try
                {
                    byte[] ENmsg = SymmetricEncryptionStandardExampleAESGCM.Encrypt(plaintext, key, nonce);
                    Console.WriteLine("encryptedmsg: " + Convert.ToBase64String(ENmsg));

                    string DECmsg = SymmetricEncryptionStandardExampleAESGCM.Decrypt(ENmsg, key);
                    Console.WriteLine("Decreptedmsg: " + DECmsg);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error {ex.Message}");
                }
            }
            //public static byte[] GenerateAES256Key()
            //{
            //    using (Aes aes = Aes.Create())
            //    {
            //        aes.KeySize = 256;
            //        aes.GenerateKey();
            //        return aes.Key;
            //    }
            //}
        public static byte[] GenerateKeyBytes(string key)
        {
            byte[] byteArray = Convert.FromBase64String(key);
            return byteArray;
        }
       
        public static byte[] GenerateRandomNonce()
            {
                byte[] nonce = new byte[12];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(nonce);

                }
                return nonce;
            }

            public static void RSA_trigger(string plaintext)
            {
                RSADEMO.RSAMethod(plaintext);
            }
            public static void SHA256_trigger(string plaintext)
            {
                SHACompute.SHAComputeMethod(plaintext);
            }
            public static void HMACSHA256_trigger(string plaintext, string key)
            {
                HmacShaCompute.HmaShaComputeMethod(plaintext, key);
            }
        }
 
}






