#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define DEFAULT_SALT_SIZE 32      // Salt size for key derivation
#define DEFAULT_IV_SIZE 16        // IV size (128 bits)
#define DEFAULT_KEY_SIZE 32       // Key size (256 bits)
#define DEFAULT_ROUNDS 10000      // Rounds
#define DEFAULT_BLOCK_SIZE 16      // 128 bits
#define HMAC_KEY_SIZE 32          // Key size for HMAC (256 bits)

// Function prototypes
void generate_random_bytes(uint8_t *buffer, size_t size);
void pbkdf2(const char *password, uint8_t *salt, int salt_len, uint8_t *output, int output_len, int iterations);
void xor_buffers(uint8_t *a, uint8_t *b, uint8_t *result, size_t length);
void generate_hmac(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len, uint8_t *hmac_out);
int are_equal(const uint8_t *a, const uint8_t *b, size_t length);

// EonaCatCipher structure
typedef struct {
    uint8_t derived_key[DEFAULT_KEY_SIZE];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    int iv_size;
    int key_size;
    int rounds;
    int block_size;
} EonaCatCipher;

// EonaCatCrypto structure
typedef struct {
    uint8_t *key;
    uint8_t *nonce;
    int block_size;
    int rounds;
    uint64_t *state;
    uint32_t block_counter;
} EonaCatCrypto;

// Function to create and initialize EonaCatCipher
EonaCatCipher* eonacat_cipher_create(const char *password) {
    if (password == NULL || strlen(password) == 0) {
        fprintf(stderr, "EonaCatCipher: Password cannot be null or empty.\n");
        return NULL;
    }

    EonaCatCipher *cipher = malloc(sizeof(EonaCatCipher));
    if (!cipher) {
        fprintf(stderr, "EonaCatCipher: Memory allocation failed.\n");
        return NULL;
    }

    cipher->iv_size = DEFAULT_IV_SIZE;
    cipher->key_size = DEFAULT_KEY_SIZE;
    cipher->rounds = DEFAULT_ROUNDS;
    cipher->block_size = DEFAULT_BLOCK_SIZE;

    uint8_t salt[DEFAULT_SALT_SIZE];
    generate_random_bytes(salt, sizeof(salt));
    pbkdf2(password, salt, sizeof(salt), cipher->derived_key, sizeof(cipher->derived_key), cipher->rounds);
    pbkdf2(password, salt, sizeof(salt), cipher->hmac_key, sizeof(cipher->hmac_key), cipher->rounds);

    return cipher;
}

// Function to clean up and free EonaCatCipher
void eonacat_cipher_destroy(EonaCatCipher *cipher) {
    if (cipher) {
        memset(cipher, 0, sizeof(EonaCatCipher));
        free(cipher);
    }
}

// PBKDF2 implementation
void pbkdf2(const char *password, uint8_t *salt, int salt_len, uint8_t *output, int output_len, int iterations) {
    int hash_len = SHA256_DIGEST_LENGTH;
    int blocks_needed = (output_len + hash_len - 1) / hash_len;

    uint8_t u[hash_len];
    uint8_t t[hash_len];

    for (int block_index = 1; block_index <= blocks_needed; block_index++) {
        // Step 1: F(block_index)
        uint8_t block[salt_len + 4];
        memcpy(block, salt, salt_len);
        uint32_t block_index_network = htonl(block_index);
        memcpy(block + salt_len, &block_index_network, 4);

        // Step 2: U1 = HMAC(password, salt + block_index)
        unsigned int len = 0;
        HMAC(EVP_sha256(), password, strlen(password), block, sizeof(block), u, &len);

        memcpy(t, u, hash_len);
        memcpy(output + (block_index - 1) * hash_len, t, (block_index == blocks_needed && output_len % hash_len != 0) ? output_len % hash_len : hash_len);

        // Step 4: Iterations
        for (int iteration = 1; iteration < iterations; iteration++) {
            // U2 = HMAC(password, U1)
            HMAC(EVP_sha256(), password, strlen(password), u, hash_len, u, &len);
            xor_buffers(t, u, t, hash_len);
            memcpy(output + (block_index - 1) * hash_len, t, (block_index == blocks_needed && output_len % hash_len != 0) ? output_len % hash_len : hash_len);
        }
    }
}

// Function to generate random bytes
void generate_random_bytes(uint8_t *buffer, size_t size) {
    RAND_bytes(buffer, size);
}

// Function to perform XOR operation on two buffers
void xor_buffers(uint8_t *a, uint8_t *b, uint8_t *result, size_t length) {
    for (size_t i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// Function to generate HMAC
void generate_hmac(uint8_t *data, size_t data_len, uint8_t *key, size_t key_len, uint8_t *hmac_out) {
    unsigned int len = 0;
    HMAC(EVP_sha256(), key, key_len, data, data_len, hmac_out, &len);
}

// Function to compare two buffers
int are_equal(const uint8_t *a, const uint8_t *b, size_t length) {
    return (memcmp(a, b, length) == 0);
}

// Function to encrypt plaintext
uint8_t* eonacat_cipher_encrypt(EonaCatCipher *cipher, const char *plaintext, size_t *out_len) {
    uint8_t iv[cipher->iv_size];
    generate_random_bytes(iv, cipher->iv_size);

    size_t plaintext_len = strlen(plaintext);
    uint8_t *ciphertext = malloc(plaintext_len + cipher->iv_size);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    memcpy(ciphertext, iv, cipher->iv_size); // Combine IV and ciphertext
    uint8_t encrypted[plaintext_len];

    EonaCatCrypto crypto;
    crypto.key = cipher->derived_key;
    crypto.nonce = iv;
    crypto.block_size = cipher->block_size;
    crypto.rounds = cipher->rounds;
    crypto.block_counter = 0;
    crypto.state = calloc(cipher->block_size / 4, sizeof(uint64_t));

    // Encrypt the plaintext (dummy XOR for demonstration purposes)
    for (size_t i = 0; i < plaintext_len; i++) {
        encrypted[i] = plaintext[i] ^ iv[i % cipher->iv_size];
    }

    memcpy(ciphertext + cipher->iv_size, encrypted, plaintext_len); // Append ciphertext

    // Generate HMAC for integrity check
    uint8_t hmac[HMAC_KEY_SIZE];
    generate_hmac(ciphertext, plaintext_len + cipher->iv_size, cipher->hmac_key, sizeof(cipher->hmac_key), hmac);

    *out_len = plaintext_len + cipher->iv_size + HMAC_KEY_SIZE;
    uint8_t *final_result = realloc(ciphertext, *out_len);
    if (!final_result) {
        free(ciphertext);
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    memcpy(final_result + *out_len - HMAC_KEY_SIZE, hmac, HMAC_KEY_SIZE); // Combine result and HMAC

    return final_result;
}

// Function to decrypt ciphertext
char* eonacat_cipher_decrypt(EonaCatCipher *cipher, uint8_t *ciphertext_with_hmac, size_t ciphertext_len) {
    uint8_t provided_hmac[HMAC_KEY_SIZE];
    memcpy(provided_hmac, ciphertext_with_hmac + ciphertext_len - HMAC_KEY_SIZE, HMAC_KEY_SIZE);

    size_t ciphertext_size = ciphertext_len - HMAC_KEY_SIZE;
    uint8_t *ciphertext = malloc(ciphertext_size);
    if (!ciphertext) {
        fprintf(stderr, "EonaCatCipher: Memory allocation failed.\n");
        return NULL;
    }

    memcpy(ciphertext, ciphertext_with_hmac, ciphertext_size); // Separate HMAC from the ciphertext

    // Verify HMAC before decrypting
    uint8_t calculated_hmac[HMAC_KEY_SIZE];
    generate_hmac(ciphertext, ciphertext_size, cipher->hmac_key, sizeof(cipher->hmac_key), calculated_hmac);
    if (!are_equal(provided_hmac, calculated_hmac, HMAC_KEY_SIZE)) {
        free(ciphertext);
        fprintf(stderr, "EonaCatCipher: HMAC validation failed. Data may have been tampered with.\n");
        return NULL;
    }

    uint8_t iv[cipher->iv_size];
    memcpy(iv, ciphertext, cipher->iv_size); // Extract IV

    size_t plaintext_len = ciphertext_size - cipher->iv_size;
    char *plaintext = malloc(plaintext_len + 1);
    if (!plaintext) {
        free(ciphertext);
        fprintf(stderr, "EonaCatCipher: Memory allocation failed.\n");
        return NULL;
    }

    // Decrypt
    for (size_t i = 0; i < plaintext_len; i++) {
        plaintext[i] = ciphertext[cipher->iv_size + i] ^ iv[i % cipher->iv_size];
    }

    plaintext[plaintext_len] = '\0'; // Null-terminate the plaintext

    free(ciphertext);
    return plaintext;
}

// Main function to demonstrate encryption and decryption
int main() {
    const char *password = "securePassword123!@#$";
    const char *plaintext = "Thank you for using EonaCatCipher!";
    size_t out_len;

    printf("Encrypting '%s' with password '%s'\n", plaintext, password);
    printf("================\n");

    EonaCatCipher *cipher = eonacat_cipher_create(password);
    if (!cipher) return 1;

    for (int i = 0; i < 5; i++) {
        printf("Encryption round %d: \n", i + 1);
        printf("================\n");

        uint8_t *encrypted = eonacat_cipher_encrypt(cipher, plaintext, &out_len);
        if (encrypted) {
            printf("Encrypted (byte array): ");
            for (size_t j = 0; j < out_len; j++) {
                printf("%02X", encrypted[j]);
            }
            printf("\n");

            char *decrypted = eonacat_cipher_decrypt(cipher, encrypted, out_len);
            if (decrypted) {
                printf("Decrypted: %s\n", decrypted);
                free(decrypted);
            }

            free(encrypted);
        }

        printf("================\n");
    }

    eonacat_cipher_destroy(cipher);
    return 0;
}
