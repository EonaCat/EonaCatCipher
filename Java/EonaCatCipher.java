import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class EonaCatCipher implements AutoCloseable {
    private static final int DEFAULT_SALT_SIZE = 2048;     // Salt size for key derivation
    private static final int DEFAULT_IV_SIZE = 2048;       // IV size (16384 bits)
    private static final int DEFAULT_KEY_SIZE = 2048;      // Key size (16384 bits)
    private static final int DEFAULT_ROUNDS = 2048;        // Rounds
    private static final int DEFAULT_BLOCK_SIZE = 8192;    // 8kb
    private static final int HMAC_KEY_SIZE = 32;           // Key size for HMAC (256 bits)

    private final byte[] derivedKey;    // Derived encryption key
    private final byte[] hmacKey;       // HMAC key
    private final int ivSize;           // IV size
    private final int keySize;          // Key size
    private final int rounds;           // Number of rounds for key derivation
    private final int blockSize;        // The size of the block that is created

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

    public EonaCatCipher(String password, int saltSize, int ivSize, int keySize, int rounds, int blockSize) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        this.ivSize = ivSize;
        this.keySize = keySize;
        this.rounds = rounds;
        this.blockSize = blockSize;

        // Derive encryption key and HMAC key
        var keys = deriveKeyAndHMAC(password, saltSize);
        this.derivedKey = keys[0];
        this.hmacKey = keys[1];
    }

    private static byte[] generateRandomBytes(int size) {
        byte[] randomBytes = new byte[size];
        new SecureRandom().nextBytes(randomBytes);
        return randomBytes;
    }

    private byte[][] deriveKeyAndHMAC(String password, int saltSize) {
        byte[] salt = generateRandomBytes(saltSize);
        byte[] encryptionKey = PBKDF2(password, salt, keySize, rounds);

        // Derive separate key for HMAC
        byte[] hmacKey = PBKDF2(password, salt, HMAC_KEY_SIZE, rounds);

        byte[] keyWithSalt = new byte[saltSize + keySize];
        System.arraycopy(salt, 0, keyWithSalt, 0, saltSize);
        System.arraycopy(encryptionKey, 0, keyWithSalt, saltSize, keySize);

        return new byte[][]{keyWithSalt, hmacKey};
    }

    private static byte[] PBKDF2(String password, byte[] salt, int keyLength, int iterations) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(password.getBytes(), "HmacSHA512"));

            int hashLength = mac.getMacLength();
            int requiredBytes = keyLength;
            int blocksNeeded = (int) Math.ceil((double) requiredBytes / hashLength);

            byte[] derivedKey = new byte[requiredBytes];
            byte[] block = new byte[hashLength];

            for (int blockIndex = 1; blockIndex <= blocksNeeded; blockIndex++) {
                // Step 1: F(blockIndex)
                byte[] currentBlock = new byte[salt.length + 4];
                System.arraycopy(salt, 0, currentBlock, 0, salt.length);
                System.arraycopy(intToBytes(blockIndex), 0, currentBlock, salt.length, 4);

                // Step 2: U1 = HMAC(password, salt + blockIndex)
                byte[] u = mac.doFinal(currentBlock);
                System.arraycopy(u, 0, block, 0, hashLength);

                // Step 3: Derived key starts with U1
                System.arraycopy(u, 0, derivedKey, (blockIndex - 1) * hashLength, Math.min(hashLength, requiredBytes));

                // Step 4: Iterations
                for (int iteration = 1; iteration < iterations; iteration++) {
                    // U2 = HMAC(password, U1)
                    u = mac.doFinal(u);

                    // Step 5: XOR U2 with previous result
                    for (int i = 0; i < hashLength; i++) {
                        block[i] ^= u[i];
                    }

                    // Step 6: Append result to derived key
                    System.arraycopy(block, 0, derivedKey, (blockIndex - 1) * hashLength, Math.min(hashLength, requiredBytes));
                }
            }

            return derivedKey;
        } catch (Exception e) {
            throw new RuntimeException("EonaCatCipher: Error during PBKDF2 processing", e);
        }
    }

    public byte[] encrypt(String plaintext) {
        byte[] iv = generateRandomBytes(ivSize);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertext = new byte[plaintextBytes.length];

        try (EonaCatCrypto cipher = new EonaCatCrypto(derivedKey, iv, blockSize, rounds)) {
            cipher.generate(plaintextBytes, ciphertext, true);
        }

        // Combine IV and ciphertext
        byte[] result = new byte[ivSize + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, ivSize);
        System.arraycopy(ciphertext, 0, result, ivSize, ciphertext.length);

        // Generate HMAC for integrity check
        byte[] hmac = generateHMAC(result);

        // Combine result and HMAC
        byte[] finalResult = new byte[result.length + hmac.length];
        System.arraycopy(result, 0, finalResult, 0, result.length);
        System.arraycopy(hmac, 0, finalResult, result.length, hmac.length);

        return finalResult;
    }

    public String decrypt(byte[] ciphertextWithHMAC) {
        int hmacOffset = ciphertextWithHMAC.length - HMAC_KEY_SIZE;

        // Separate HMAC from the ciphertext
        byte[] providedHMAC = new byte[HMAC_KEY_SIZE];
        System.arraycopy(ciphertextWithHMAC, hmacOffset, providedHMAC, 0, HMAC_KEY_SIZE);

        byte[] ciphertext = new byte[hmacOffset];
        System.arraycopy(ciphertextWithHMAC, 0, ciphertext, 0, hmacOffset);

        // Verify HMAC before decrypting
        byte[] calculatedHMAC = generateHMAC(ciphertext);
        if (!Arrays.equals(providedHMAC, calculatedHMAC)) {
            throw new RuntimeException("EonaCatCipher: HMAC validation failed. Data may have been tampered with.");
        }

        // Extract IV
        byte[] iv = new byte[ivSize];
        System.arraycopy(ciphertext, 0, iv, 0, ivSize);

        // Extract encrypted data
        byte[] encryptedData = new byte[ciphertext.length - ivSize];
        System.arraycopy(ciphertext, ivSize, encryptedData, 0, encryptedData.length);

        // Decrypt
        byte[] decryptedData = new byte[encryptedData.length];
        try (EonaCatCrypto cipher = new EonaCatCrypto(derivedKey, iv, blockSize, rounds)) {
            cipher.generate(encryptedData, decryptedData, false);
        }

        return new String(decryptedData);
    }

    private byte[] generateHMAC(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("EonaCatCipher: Error generating HMAC", e);
        }
    }

    private static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    @Override
    public void close() {
        if (derivedKey != null) {
            Arrays.fill(derivedKey, (byte) 0);
        }
        if (hmacKey != null) {
            Arrays.fill(hmacKey, (byte) 0);
        }
    }

    private static class EonaCatCrypto implements AutoCloseable {
        private static final long SECRET_SAUCE = 0x5DEECE66D;
        private static final long UNSIGNED_INT = 0xFFFFFFFF;
        private final int blockSize;
        private final int rounds;
        private final long[] state;
        private final long[] key;
        private final long[] nonce;
        private long blockCounter;

        public EonaCatCrypto(byte[] keyWithSalt, byte[] nonce, int blockSize, int rounds) {
            this.rounds = rounds;
            this.blockSize = blockSize / 4 > 0 ? blockSize : 128;

            this.key = new long[keyWithSalt.length / 8];
            for (int i = 0; i < key.length; i++) {
                key[i] = bytesToLong(keyWithSalt, i * 8);
            }

            this.nonce = new long[nonce.length / 8];
            for (int i = 0; i < nonce.length / 8; i++) {
                nonce[i] = bytesToLong(nonce, i * 8);
            }

            this.state = new long[blockSize / 8];
        }

        private void generateBlock(byte[] output) {
            // Initialize state using a combined operation
            for (int i = 0; i < state.length; i++) {
                state[i] = (key[i % key.length] ^ nonce[i % nonce.length]) + (long) i * SECRET_SAUCE;
            }

            // Mix the states according to the rounds
            for (int round = 0; round < rounds; round++) {
                for (int i = 0; i < state.length; i++) {
                    state[i] = (long) (((int) state[i] + round) ^ (round * SECRET_SAUCE) + (i + blockCounter));
                }
            }

            // Output block
            for (int i = 0; i < output.length; i++) {
                output[i] = (byte) state[i % state.length];
            }
            blockCounter++;
        }

        public void generate(byte[] input, byte[] output, boolean encrypt) {
            int totalBlocks = (input.length + blockSize - 1) / blockSize;

            for (int blockIndex = 0; blockIndex < totalBlocks; blockIndex++) {
                int inputOffset = blockIndex * blockSize;
                int outputOffset = blockIndex * blockSize;
                byte[] block = new byte[blockSize];

                // Generate a block based on the input
                generateBlock(block);

                // Perform XOR for encryption or decryption
                for (int i = 0; i < block.length && inputOffset + i < input.length; i++) {
                    output[outputOffset + i] = (byte) (input[inputOffset + i] ^ block[i]);
                }
            }
        }

        @Override
        public void close() {
            if (state != null) {
                Arrays.fill(state, 0);
            }
        }

        private long bytesToLong(byte[] bytes, int offset) {
            return ((long) bytes[offset] & UNSIGNED_INT) << 56 |
                    ((long) bytes[offset + 1] & UNSIGNED_INT) << 48 |
                    ((long) bytes[offset + 2] & UNSIGNED_INT) << 40 |
                    ((long) bytes[offset + 3] & UNSIGNED_INT) << 32 |
                    ((long) bytes[offset + 4] & UNSIGNED_INT) << 24 |
                    ((long) bytes[offset + 5] & UNSIGNED_INT) << 16 |
                    ((long) bytes[offset + 6] & UNSIGNED_INT) << 8 |
                    ((long) bytes[offset + 7] & UNSIGNED_INT);
        }
    }

    public static void main(String[] args) {
        String password = "securePassword123!@#$";
        String plaintext = "Thank you for using EonaCatCipher!";

        System.out.println("Encrypting '" + plaintext + "' with password '" + password + "' (we do this 5 times)");
        System.out.println("================");

        for (int i = 0; i < 5; i++) {
            System.out.println("Encryption round " + (i + 1) + ": ");
            System.out.println("================");

            try (EonaCatCipher cipher = new EonaCatCipher(password, DEFAULT_SALT_SIZE, DEFAULT_IV_SIZE, DEFAULT_KEY_SIZE, DEFAULT_ROUNDS, DEFAULT_BLOCK_SIZE)) {
                byte[] encrypted = cipher.encrypt(plaintext);
                System.out.println("Encrypted (byte array): " + Base64.getEncoder().encodeToString(encrypted));

                String decrypted = cipher.decrypt(encrypted);
                System.out.println("Decrypted: " + decrypted);
                System.out.println("================");
            }
        }
    }
}
