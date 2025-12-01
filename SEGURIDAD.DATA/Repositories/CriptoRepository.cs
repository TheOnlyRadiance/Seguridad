using SEGURIDAD.DATA.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SEGURIDAD.DATA.Repositories
{
    public class CriptoRepository : ICryptoService
    {
        private readonly byte[] _key; // 32 bytes para AES-256

        public CriptoRepository(byte[] key)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("La llave debe tener 32 bytes para AES-256.");

            _key = key;
        }

        public string EncryptToBase64(string plainText)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] iv = new byte[12]; // recomendado para GCM
            RandomNumberGenerator.Fill(iv);

            byte[] cipherBytes = new byte[plainBytes.Length];
            byte[] tag = new byte[16]; // Tag de autenticación

            using var aes = new AesGcm(_key);
            aes.Encrypt(iv, plainBytes, cipherBytes, tag);

            // combinar IV + TAG + CIPHER en un solo bloque
            byte[] data = new byte[iv.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(iv, 0, data, 0, iv.Length);
            Buffer.BlockCopy(tag, 0, data, iv.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, data, iv.Length + tag.Length, cipherBytes.Length);

            return Convert.ToBase64String(data);
        }

        public string DecryptFromBase64(string cipherTextBase64)
        {
            byte[] allBytes = Convert.FromBase64String(cipherTextBase64);

            byte[] iv = allBytes[..12];
            byte[] tag = allBytes[12..28];
            byte[] cipher = allBytes[28..];

            byte[] plainBytes = new byte[cipher.Length];

            using var aes = new AesGcm(_key);
            aes.Decrypt(iv, cipher, tag, plainBytes);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
