#include <iostream>
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

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

class EonaCatCrypto {
private:
    static const uint64_t SECRET_SAUCE = 0x5DEECE66D;
    const int _blockSize;
    const int _rounds;
    uint64_t* _state;
    uint32_t* _key;
    uint32_t* _nonce;
    uint32_t _blockCounter;

    void GenerateBlock(uint8_t* output) {
        for (int i = 0; i < _blockSize / 4; i++) {
            _state[i] = (_key[i % (_blockSize / 4)] ^ _nonce[i % (_blockSize / 4)]) + (uint64_t)i * SECRET_SAUCE;
        }

        for (int round = 0; round < _rounds; round++) {
            for (int i = 0; i < _blockSize / 4; i++) {
                _state[i] = (uint64_t)(((int)_state[i] + round) ^ (round * SECRET_SAUCE) + (i + _blockCounter));
            }
        }

        memcpy(output, _state, _blockSize);
        _blockCounter++;
    }

public:
    EonaCatCrypto(const uint8_t* keyWithSalt, const uint8_t* nonce, int blockSize, int rounds)
        : _blockSize(blockSize), _rounds(rounds), _blockCounter(0) {
        _key = new uint32_t[_blockSize / 4];
        memcpy(_key, keyWithSalt, _blockSize / 4 * sizeof(uint32_t));

        _nonce = new uint32_t[blockSize / 4];
        memcpy(_nonce, nonce, blockSize / 4 * sizeof(uint32_t));

        _state = new uint64_t[_blockSize / 4];
    }

    ~EonaCatCrypto() {
        delete[] _key;
        delete[] _nonce;
        delete[] _state;
    }

    void Generate(const uint8_t* input, uint8_t* output, bool encrypt) {
        int totalBlocks = (strlen((const char*)input) + _blockSize - 1) / _blockSize;

        for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++) {
            int inputOffset = blockIndex * _blockSize;
            int outputOffset = blockIndex * _blockSize;
            uint8_t block[_blockSize];

            GenerateBlock(block);

            for (int i = 0; i < _blockSize && inputOffset + i < strlen((const char*)input); i++) {
                output[outputOffset + i] = input[inputOffset + i] ^ block[i];
            }
        }
    }
};

class EonaCatCipher {
private:
    const int DEFAULT_SALT_SIZE = 2048;     // Salt size for key derivation
    const int DEFAULT_IV_SIZE = 2048;       // IV size (16384 bits)
    const int DEFAULT_KEY_SIZE = 2048;      // Key size (16384 bits)
    const int DEFAULT_ROUNDS = 2048;        // Rounds
    const int DEFAULT_BLOCK_SIZE = 8192;    // 8kb
    const int HMAC_KEY_SIZE = 32;           // Key size for HMAC (256 bits)
    
    uint8_t* _derivedKey;               // Derived encryption key
    uint8_t* _hmacKey;                  // HMAC key
    int _ivSize;                        // IV size
    int _keySize;                       // Key size
    int _rounds;                        // Number of rounds for key derivation
    int _blockSize;                     // The size of the block that is created

    static std::vector<uint8_t> GenerateRandomBytes(int size) {
        std::vector<uint8_t> randomBytes(size);
        if (!RAND_bytes(randomBytes.data(), size)) {
            throw std::runtime_error("EonaCatCipher: Failed to generate random bytes.");
        }
        return randomBytes;
    }

    void DeriveKeyAndHMAC(const std::string& password, int saltSize) {
        std::vector<uint8_t> salt = GenerateRandomBytes(saltSize);
        _derivedKey = PBKDF2(password, salt.data(), salt.size(), _keySize);
        _hmacKey = PBKDF2(password, salt.data(), salt.size(), HMAC_KEY_SIZE);
    }

    uint8_t* PBKDF2(const std::string& password, const uint8_t* salt, int saltLen, int keyLength) {
        uint8_t* derivedKey = new uint8_t[keyLength];
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, saltLen, _rounds, EVP_sha256(), keyLength, derivedKey);
        return derivedKey;
    }

    std::vector<uint8_t> GenerateHMAC(const uint8_t* data, size_t dataLen) {
        std::vector<uint8_t> hmac(EVP_MAX_MD_SIZE);
        unsigned int hmacLen;
        HMAC(EVP_sha256(), _hmacKey, HMAC_KEY_SIZE, data, dataLen, hmac.data(), &hmacLen);
        hmac.resize(hmacLen);
        return hmac;
    }

    bool AreEqual(const uint8_t* a, const uint8_t* b, size_t length) {
        return CRYPTO_memcmp(a, b, length) == 0;
    }

public:
    EonaCatCipher(const std::string& password, int saltSize = 32, int ivSize = 16, int keySize = 32, int rounds = 1000, int blockSize = 128)
        : _ivSize(ivSize), _keySize(keySize), _rounds(rounds), _blockSize(blockSize), _derivedKey(nullptr), _hmacKey(nullptr) {
        if (password.empty()) {
            throw std::invalid_argument("EonaCatCipher: Password cannot be null or empty.");
        }
        DeriveKeyAndHMAC(password, saltSize);
    }

    ~EonaCatCipher() {
        delete[] _derivedKey;
        delete[] _hmacKey;
    }

    std::vector<uint8_t> Encrypt(const std::string& plaintext) {
        auto iv = GenerateRandomBytes(_ivSize);
        std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
        std::vector<uint8_t> ciphertext(plaintextBytes.size());

        EonaCatCrypto cipher(_derivedKey, iv.data(), _blockSize, _rounds);
        cipher.Generate(plaintextBytes.data(), ciphertext.data(), true);

        std::vector<uint8_t> result(_ivSize + ciphertext.size());
        memcpy(result.data(), iv.data(), _ivSize);
        memcpy(result.data() + _ivSize, ciphertext.data(), ciphertext.size());

        auto hmac = GenerateHMAC(result.data(), result.size());
        result.insert(result.end(), hmac.begin(), hmac.end());

        return result;
    }

    std::string Decrypt(const std::vector<uint8_t>& ciphertextWithHMAC) {
        size_t hmacOffset = ciphertextWithHMAC.size() - HMAC_KEY_SIZE;

        std::vector<uint8_t> providedHMAC(HMAC_KEY_SIZE);
        memcpy(providedHMAC.data(), ciphertextWithHMAC.data() + hmacOffset, HMAC_KEY_SIZE);

        std::vector<uint8_t> ciphertext(hmacOffset);
        memcpy(ciphertext.data(), ciphertextWithHMAC.data(), hmacOffset);

        auto calculatedHMAC = GenerateHMAC(ciphertext.data(), ciphertext.size());
        if (!AreEqual(providedHMAC.data(), calculatedHMAC.data(), HMAC_KEY_SIZE)) {
            throw std::runtime_error("EonaCatCipher: HMAC validation failed. Data may have been tampered with.");
        }

        std::vector<uint8_t> iv(_ivSize);
        memcpy(iv.data(), ciphertext.data(), _ivSize);

        std::vector<uint8_t> encryptedData(ciphertext.size() - _ivSize);
        memcpy(encryptedData.data(), ciphertext.data() + _ivSize, encryptedData.size());

        std::vector<uint8_t> decryptedData(encryptedData.size());
        EonaCatCrypto decryptCipher(_derivedKey, iv.data(), _blockSize, _rounds);
        decryptCipher.Generate(encryptedData.data(), decryptedData.data(), false);

        return std::string(decryptedData.begin(), decryptedData.end());
    }

    static void Main() {
        std::string password = "securePassword123!@#$";
        std::string plaintext = "Thank you for using EonaCatCipher!";

        std::cout << "Encrypting '" << plaintext << "' with password '" << password << "' (we do this 5 times)" << std::endl;
        std::cout << "================" << std::endl;

        for (int i = 0; i < 5; i++) {
            std::cout << "Encryption round " << (i + 1) << ": " << std::endl;
            std::cout << "================" << std::endl;

            try {
                EonaCatCipher cipher(password);
                auto encrypted = cipher.Encrypt(plaintext);
                std::cout << "Encrypted (byte array): ";
                for (auto byte : encrypted) {
                    printf("%02X ", byte);
                }
                std::cout << std::endl;

                std::string decrypted = cipher.Decrypt(encrypted);
                std::cout << "Decrypted: " << decrypted << std::endl;
                std::cout << "================" << std::endl;
            }
            catch (const std::exception& ex) {
                std::cerr << "Error: " << ex.what() << std::endl;
            }
        }
    }
};

int main() {
    EonaCatCipher::Main();
    return 0;
}
