package main

import (
    "crypto/rand"
    "crypto/sha512"
    "crypto/hmac"
    "encoding/binary"
    "encoding/hex"
    "encoding/base64"
    "fmt"
    "log"
)

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

// EonaCatCipher struct
type EonaCatCipher struct {
    derivedKey []byte
    hmacKey    []byte
    ivSize     int
    keySize    int
    rounds     int
    blockSize  int
}

// Constants
const (
    DEFAULT_SALT_SIZE  = 2048 // Salt size for key derivation
    DEFAULT_IV_SIZE    = 2048    // IV size (16384 bits)
    DEFAULT_KEY_SIZE   = 2048    // Key size (16384 bits)
    DEFAULT_ROUNDS     = 2048
    DEFAULT_BLOCK_SIZE = 8192  // 8KB
    HMAC_KEY_SIZE      = 32    // Key size for HMAC (256 bits)
    SECRET_SAUCE       = 0x5DEECE66D
)

// NewEonaCatCipher constructor
func NewEonaCatCipher(password string, saltSize int, ivSize int, keySize int, rounds int, blockSize int) *EonaCatCipher {
    if password == "" {
        log.Fatal("EonaCatCipher: Password cannot be null or empty.")
    }

    ec := &EonaCatCipher{
        ivSize:    ivSize,
        keySize:   keySize,
        rounds:    rounds,
        blockSize: blockSize,
    }

    ec.derivedKey, ec.hmacKey = ec.DeriveKeyAndHMAC(password, saltSize)

    return ec
}

// GenerateRandomBytes generates a slice of random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
    randomBytes := make([]byte, size)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return nil, err
    }
    return randomBytes, nil
}

// DeriveKeyAndHMAC derives the encryption key and HMAC key from the password
func (ec *EonaCatCipher) DeriveKeyAndHMAC(password string, saltSize int) ([]byte, []byte) {
    salt, _ := GenerateRandomBytes(saltSize)
    encryptionKey := ec.PBKDF2(password, salt, ec.keySize, ec.rounds)

    // Derive separate key for HMAC
    hmacKey := ec.PBKDF2(password, salt, HMAC_KEY_SIZE, ec.rounds)

    keyWithSalt := append(salt, encryptionKey...)

    return keyWithSalt, hmacKey
}

// PBKDF2 implementation of the PBKDF2 key derivation function
func (ec *EonaCatCipher) PBKDF2(password string, salt []byte, keyLength int, iterations int) []byte {
    hmacHash := hmac.New(sha512.New, []byte(password))
    hashLength := hmacHash.Size()
    requiredBytes := keyLength
    blocksNeeded := (requiredBytes + hashLength - 1) / hashLength

    derivedKey := make([]byte, requiredBytes)

    for blockIndex := 1; blockIndex <= blocksNeeded; blockIndex++ {
        currentBlock := append(salt, intToBytes(blockIndex)...)

        // U1 = HMAC(password, salt + blockIndex)
        u := hmacHash.Sum(currentBlock)
        block := make([]byte, hashLength)
        copy(block, u)

        // Derived key starts with U1
        copy(derivedKey[(blockIndex-1)*hashLength:], block)

        // Iterations
        for iteration := 1; iteration < iterations; iteration++ {
            u = hmacHash.Sum(u)

            // XOR with previous result
            for i := 0; i < hashLength; i++ {
                block[i] ^= u[i]
            }

            // Append result to derived key
            copy(derivedKey[(blockIndex-1)*hashLength:], block)
        }
    }

    return derivedKey
}

// Encrypt encrypts the plaintext using the derived key and returns the ciphertext with HMAC
func (ec *EonaCatCipher) Encrypt(plaintext string) ([]byte, error) {
    iv, err := GenerateRandomBytes(ec.ivSize)
    if err != nil {
        return nil, err
    }
    plaintextBytes := []byte(plaintext)
    ciphertext := make([]byte, len(plaintextBytes))

    cipher := NewEonaCatCrypto(ec.derivedKey, iv, ec.blockSize, ec.rounds)
    cipher.Generate(plaintextBytes, ciphertext, true)

    // Combine IV and ciphertext
    result := append(iv, ciphertext...)

    // Generate HMAC for integrity check
    hmac := ec.GenerateHMAC(result)

    // Combine result and HMAC
    finalResult := append(result, hmac...)

    return finalResult, nil
}

// Decrypt decrypts the ciphertext with HMAC
func (ec *EonaCatCipher) Decrypt(ciphertextWithHMAC []byte) (string, error) {
    hmacOffset := len(ciphertextWithHMAC) - HMAC_KEY_SIZE

    // Separate HMAC from the ciphertext
    providedHMAC := ciphertextWithHMAC[hmacOffset:]
    ciphertext := ciphertextWithHMAC[:hmacOffset]

    // Verify HMAC before decrypting
    calculatedHMAC := ec.GenerateHMAC(ciphertext)
    if !AreEqual(providedHMAC, calculatedHMAC) {
        return "", fmt.Errorf("EonaCatCipher: HMAC validation failed. Data may have been tampered with.")
    }

    // Extract IV
    iv := ciphertext[:ec.ivSize]

    // Extract encrypted data
    encryptedData := ciphertext[ec.ivSize:]

    // Decrypt
    decryptedData := make([]byte, len(encryptedData))
    cipher := NewEonaCatCrypto(ec.derivedKey, iv, ec.blockSize, ec.rounds)
    cipher.Generate(encryptedData, decryptedData, false)

    return string(decryptedData), nil
}

// GenerateHMAC generates HMAC for the data
func (ec *EonaCatCipher) GenerateHMAC(data []byte) []byte {
    h := hmac.New(sha512.New, ec.hmacKey)
    h.Write(data)
    return h.Sum(nil)
}

// AreEqual checks if two byte slices are equal
func AreEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// Convert an integer to bytes
func intToBytes(n int) []byte {
    buf := make([]byte, 4)
    binary.BigEndian.PutUint32(buf, uint32(n))
    return buf
}

// EonaCatCrypto struct for encryption and decryption
type EonaCatCrypto struct {
    blockSize    int
    rounds       int
    state        []uint64
    key          []uint32
    nonce        []uint32
    blockCounter uint32
}

// NewEonaCatCrypto constructor
func NewEonaCatCrypto(keyWithSalt []byte, nonce []byte, blockSize int, rounds int) *EonaCatCrypto {
    ec := &EonaCatCrypto{
        blockSize: blockSize / 4,
        rounds:    rounds,
        key:       make([]uint32, len(keyWithSalt)/4),
        nonce:     make([]uint32, len(nonce)/4),
        state:     make([]uint64, blockSize/4),
    }
    copy(ec.key, keyWithSalt)
    copy(ec.nonce, nonce)
    return ec
}

// GenerateBlock generates a block for encryption/decryption
func (ec *EonaCatCrypto) GenerateBlock(output []byte) {
    // Initialize state
    for i := 0; i < len(ec.state); i++ {
        ec.state[i] = uint64(ec.key[i%len(ec.key)]) ^ uint64(ec.nonce[i%len(ec.nonce)]) + uint64(i)*SECRET_SAUCE
    }

    // Mix the states according to the rounds
    for round := 0; round < ec.rounds; round++ {
        for i := 0; i < len(ec.state); i++ {
            ec.state[i] = (ec.state[i] + uint64(round)) ^ (uint64(round) * SECRET_SAUCE) + uint64(i) + uint64(ec.blockCounter)
        }
    }

    // Output block
    for i := 0; i < len(output); i++ {
        output[i] = byte(ec.state[i/4] >> (8 * (i % 4)))
    }
    ec.blockCounter++
}

// Generate performs encryption or decryption
func (ec *EonaCatCrypto) Generate(input []byte, output []byte, encrypt bool) {
    totalBlocks := (len(input) + ec.blockSize - 1) / ec.blockSize

    for blockIndex := 0; blockIndex < totalBlocks; blockIndex++ {
        inputOffset := blockIndex * ec.blockSize
        outputOffset := blockIndex * ec.blockSize
        block := make([]byte, ec.blockSize)

        // Generate a block based on the input
        ec.GenerateBlock(block)

        // Perform XOR for encryption or decryption
        for i := 0; i < len(block) && inputOffset+i < len(input); i++ {
            output[outputOffset+i] = input[inputOffset+i] ^ block[i]
        }
    }
}

// Main function for testing
func main() {
    password := "securePassword123!@#$"
    plaintext := "Thank you for using EonaCatCipher!"

    fmt.Printf("Encrypting '%s' with password '%s' (we do this 5 times)\n", plaintext, password)
    fmt.Println("================")

    for i := 0; i < 5; i++ {
        fmt.Printf("Encryption round %d:\n", i+1)
        fmt.Println("================")

        cipher := NewEonaCatCipher(password, DEFAULT_SALT_SIZE, DEFAULT_IV_SIZE, DEFAULT_KEY_SIZE, DEFAULT_ROUNDS, DEFAULT_BLOCK_SIZE)
        encrypted, err := cipher.Encrypt(plaintext)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Encrypted (base64): %s\n", base64.StdEncoding.EncodeToString(encrypted))

        decrypted, err := cipher.Decrypt(encrypted)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Decrypted: %s\n", decrypted)
        fmt.Println("================")
    }
}
