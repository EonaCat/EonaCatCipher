using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

/*
 * EonaCatCipher - Because security is key!
 * 
 * Copyright (c) 2024 EonaCat (Jeroen Saey)
 * 
 * https://eonacat.com/license
 * 
 *   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION 
 *                  OF SOFTWARE BY EONACAT (JEROEN SAEY)
 *
 * This software is provided "as is", without any express or implied warranty.
 * In no event shall the authors or copyright holders be liable for any claim,
 * damages or other liability, whether in an action of contract, tort or otherwise,
 * arising from, out of or in connection with the software or the use or other
 * dealings in the software.
 * 
 * You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and permit persons to whom the Software is furnished 
 * to do so, subject to the following conditions:
 * 
 * 1. The above copyright notice and this permission notice shall be included in 
 *    all copies or substantial portions of the Software.
 * 
 * 2. The software must not be used for any unlawful purpose.
 * 
 * For any inquiries, please contact: eonacat@gmail.com
 */

public class EonaCatCipher : IDisposable
{
    private const int DEFAULT_SALT_SIZE = 2048;     // Salt size for key derivation
    private const int DEFAULT_IV_SIZE = 2048;       // IV size (16384 bits)
    private const int DEFAULT_KEY_SIZE = 2048;      // Key size (16384 bits)
    private const int DEFAULT_ROUNDS = 2048;        // Rounds
    private const int DEFAULT_BLOCK_SIZE = 8192;    // 8kb
    private const int HMAC_KEY_SIZE = 32;           // Key size for HMAC (256 bits)

    private readonly byte[] _derivedKey;    // Derived encryption key
    private readonly byte[] _hmacKey;       // HMAC key
    private readonly int _ivSize;           // IV size
    private readonly int _keySize;          // Key size
    private readonly int _rounds;           // Number of rounds for key derivation
    private readonly int _blockSize;        // The size of the block that is created

    public EonaCatCipher(string password, int saltSize = DEFAULT_SALT_SIZE, int ivSize = DEFAULT_IV_SIZE, int keySize = DEFAULT_KEY_SIZE, int rounds = DEFAULT_ROUNDS, int blockSize = DEFAULT_BLOCK_SIZE)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("EonaCatCipher: Password cannot be null or empty.");
        }

        _ivSize = ivSize;
        _keySize = keySize;
        _rounds = rounds;
        _blockSize = blockSize;

        // Derive encryption key and HMAC key
        (_derivedKey, _hmacKey) = DeriveKeyAndHMAC(password, saltSize);
    }

    private static byte[] GenerateRandomBytes(int size)
    {
        var randomBytes = new byte[size];
        RandomNumberGenerator.Fill(randomBytes);
        return randomBytes;
    }

    private (byte[] encryptionKey, byte[] hmacKey) DeriveKeyAndHMAC(string password, int saltSize)
    {
        var salt = GenerateRandomBytes(saltSize);
        var encryptionKey = PBKDF2(password, salt, _keySize, _rounds);

        // Derive separate key for HMAC
        var hmacKey = PBKDF2(password, salt, HMAC_KEY_SIZE, _rounds); 

        var keyWithSalt = new byte[saltSize + _keySize];
        Buffer.BlockCopy(salt, 0, keyWithSalt, 0, saltSize);
        Buffer.BlockCopy(encryptionKey, 0, keyWithSalt, saltSize, _keySize);

        return (keyWithSalt, hmacKey);
    }

    private static byte[] PBKDF2(string password, byte[] salt, int keyLength, int iterations)
    {
        var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(password));
        int hashLength = hmac.HashSize / 8;
        int requiredBytes = keyLength;
        int blocksNeeded = (int)Math.Ceiling((double)requiredBytes / hashLength);

        byte[] derivedKey = new byte[requiredBytes];
        byte[] block = new byte[hashLength];

        for (int blockIndex = 1; blockIndex <= blocksNeeded; blockIndex++)
        {
            // Step 1: F(blockIndex)
            var currentBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, currentBlock, 0, salt.Length);
            BitConverter.GetBytes(blockIndex).CopyTo(currentBlock, salt.Length);

            // Step 2: U1 = HMAC(password, salt + blockIndex)
            byte[] u = hmac.ComputeHash(currentBlock);
            Buffer.BlockCopy(u, 0, block, 0, hashLength);

            // Step 3: Derived key starts with U1
            Array.Copy(u, 0, derivedKey, (blockIndex - 1) * hashLength, Math.Min(hashLength, requiredBytes));

            // Step 4: Iterations
            for (int iteration = 1; iteration < iterations; iteration++)
            {
                // U2 = HMAC(password, U1)
                u = hmac.ComputeHash(u);

                // Step 5: XOR U2 with previous result
                for (int i = 0; i < hashLength; i++)
                {
                    block[i] ^= u[i];
                }

                // Step 6: Append result to derived key
                Array.Copy(block, 0, derivedKey, (blockIndex - 1) * hashLength, Math.Min(hashLength, requiredBytes));
            }
        }

        return derivedKey;
    }

    public byte[] Encrypt(string plaintext)
    {
        var iv = GenerateRandomBytes(_ivSize);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];

        using var cipher = new EonaCatCrypto(_derivedKey, iv, _blockSize, _rounds);
        cipher.Generate(plaintextBytes, ciphertext, true);

        // Combine IV and ciphertext
        var result = new byte[_ivSize + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, result, 0, _ivSize);
        Buffer.BlockCopy(ciphertext, 0, result, _ivSize, ciphertext.Length);

        // Generate HMAC for integrity check
        var hmac = GenerateHMAC(result);

        // Combine result and HMAC
        var finalResult = new byte[result.Length + hmac.Length];
        Buffer.BlockCopy(result, 0, finalResult, 0, result.Length);
        Buffer.BlockCopy(hmac, 0, finalResult, result.Length, hmac.Length);

        return finalResult;
    }

    public string Decrypt(byte[] ciphertextWithHMAC)
    {
        var hmacOffset = ciphertextWithHMAC.Length - HMAC_KEY_SIZE;

        // Separate HMAC from the ciphertext
        var providedHMAC = new byte[HMAC_KEY_SIZE];
        Buffer.BlockCopy(ciphertextWithHMAC, hmacOffset, providedHMAC, 0, HMAC_KEY_SIZE);

        var ciphertext = new byte[hmacOffset];
        Buffer.BlockCopy(ciphertextWithHMAC, 0, ciphertext, 0, hmacOffset);

        // Verify HMAC before decrypting
        var calculatedHMAC = GenerateHMAC(ciphertext);
        if (!AreEqual(providedHMAC, calculatedHMAC))
        {
            throw new CryptographicException("EonaCatCipher: HMAC validation failed. Data may have been tampered with.");
        }

        // Extract IV
        var iv = new byte[_ivSize];
        Buffer.BlockCopy(ciphertext, 0, iv, 0, _ivSize);

        // Extract encrypted data
        var encryptedData = new byte[ciphertext.Length - _ivSize];
        Buffer.BlockCopy(ciphertext, _ivSize, encryptedData, 0, encryptedData.Length);

        // Decrypt
        var decryptedData = new byte[encryptedData.Length];
        using var cipher = new EonaCatCrypto(_derivedKey, iv, _blockSize, _rounds);
        cipher.Generate(encryptedData, decryptedData, false);

        return Encoding.UTF8.GetString(decryptedData);
    }

    private byte[] GenerateHMAC(byte[] data)
    {
        using var hmac = new HMACSHA256(_hmacKey);
        return hmac.ComputeHash(data);
    }

    private static bool AreEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    public void Dispose()
    {
        if (_derivedKey != null)
        {
            Array.Clear(_derivedKey, 0, _derivedKey.Length);
        }
        if (_hmacKey != null)
        {
            Array.Clear(_hmacKey, 0, _hmacKey.Length);
        }
    }

    private class EonaCatCrypto : IDisposable
    {
        private const long SECRET_SAUCE = 0x5DEECE66D;
        private const uint UNSIGNED_INT = 0xFFFFFFFF;
        private readonly int _blockSize;
        private readonly int _rounds;
        private readonly ulong[] _state;
        private readonly uint[] _key;
        private readonly uint[] _nonce;
        private uint _blockCounter;

        public EonaCatCrypto(byte[] keyWithSalt, byte[] nonce, int blockSize, int rounds)
        {
            _rounds = rounds;
            _blockSize = blockSize / 4 > 0 ? blockSize : 128;

            _key = new uint[keyWithSalt.Length / 4];
            Buffer.BlockCopy(keyWithSalt, 0, _key, 0, keyWithSalt.Length);

            _nonce = new uint[nonce.Length / 4];
            Buffer.BlockCopy(nonce, 0, _nonce, 0, nonce.Length);

            _state = new ulong[_blockSize / 4];
        }

        private void GenerateBlock(byte[] output)
        {
            // Initialize state using a combined operation
            for (int i = 0; i < _state.Length; i++)
            {
                _state[i] = (_key[i % _key.Length] ^ _nonce[i % _nonce.Length]) + (ulong)i * SECRET_SAUCE;
            }

            // Mix the states according to the rounds
            for (int round = 0; round < _rounds; round++)
            {
                for (int i = 0; i < _state.Length; i++)
                {
                    _state[i] = (ulong)(((int)_state[i] + round) ^ (round * SECRET_SAUCE) + (i + _blockCounter));
                }
            }

            // Output block
            Buffer.BlockCopy(_state, 0, output, 0, output.Length);
            _blockCounter++;
        }

        public void Generate(byte[] input, byte[] output, bool encrypt)
        {
            int totalBlocks = (input.Length + _blockSize - 1) / _blockSize;

            for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
            {
                int inputOffset = blockIndex * _blockSize;
                int outputOffset = blockIndex * _blockSize;
                byte[] block = new byte[_blockSize];

                // Generate a block based on the input
                GenerateBlock(block);

                // Perform XOR for encryption or decryption
                for (int i = 0; i < block.Length && inputOffset + i < input.Length; i++)
                {
                    output[outputOffset + i] = (byte)(input[inputOffset + i] ^ block[i]);
                }
            }
        }

        public void Dispose()
        {
            if (_state != null)
            {
                Array.Clear(_state, 0, _state.Length);
            }
        }
    }

    public static void Main(string[] args)
    {
        string password = "securePassword123!@#$";
        string plaintext = "Thank you for using EonaCatCipher!";

        Console.WriteLine($"Encrypting '{plaintext}' with password '{password}' (we do this 5 times)");
        Console.WriteLine("================");

        for (int i = 0; i < 5; i++)
        {
            Console.WriteLine($"Encryption round {i + 1}: ");
            Console.WriteLine("================");

            using var cipher = new EonaCatCipher(password);
            var encrypted = cipher.Encrypt(plaintext);

            Console.WriteLine("Encrypted (byte array): " + BitConverter.ToString(encrypted));

            var decrypted = cipher.Decrypt(encrypted);

            Console.WriteLine("Decrypted: " + decrypted);
            Console.WriteLine("================");
        }
    }
}
