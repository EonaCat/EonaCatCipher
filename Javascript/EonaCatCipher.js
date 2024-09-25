class EonaCatCipher {
    constructor(password, saltSize = 2048, ivSize = 2048, keySize = 2048, rounds = 2048, blockSize = 8192) {
        if (!password) {
            throw new Error("Password cannot be null or empty.");
        }

        this.ivSize = ivSize;
        this.keySize = keySize;
        this.rounds = rounds;
        this.blockSize = blockSize;

        // Derive encryption key and HMAC key
        [this.derivedKey, this.hmacKey] = this.deriveKeyAndHMAC(password, saltSize);
    }

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

    static generateRandomBytes(size) {
        const randomBytes = new Uint8Array(size);
        crypto.getRandomValues(randomBytes);
        return randomBytes;
    }

    deriveKeyAndHMAC(password, saltSize) {
        const salt = EonaCatCipher.generateRandomBytes(saltSize);
        const encryptionKey = this.pbkdf2(password, salt, this.keySize, this.rounds);

        // Derive separate key for HMAC
        const hmacKey = this.pbkdf2(password, salt, 32, this.rounds);

        const keyWithSalt = new Uint8Array(saltSize + this.keySize);
        keyWithSalt.set(salt, 0);
        keyWithSalt.set(encryptionKey, saltSize);

        return [keyWithSalt, hmacKey];
    }

    pbkdf2(password, salt, keyLength, iterations) {
        const hmac = new Uint8Array(64); // HMAC length (SHA512)
        const hashLength = hmac.length;

        const blocksNeeded = Math.ceil(keyLength / hashLength);
        const derivedKey = new Uint8Array(keyLength);

        for (let blockIndex = 1; blockIndex <= blocksNeeded; blockIndex++) {
            const currentBlock = new Uint8Array(salt.length + 4);
            currentBlock.set(salt, 0);
            currentBlock.set(new Uint8Array(new Uint32Array([blockIndex]).buffer), salt.length);

            let u = this.hmacSha512(password, currentBlock);
            const block = new Uint8Array(hashLength);
            block.set(u);

            // Step 4: Derived key starts with U1
            derivedKey.set(u.subarray(0, Math.min(hashLength, keyLength)), (blockIndex - 1) * hashLength);

            // Step 4: Iterations
            for (let iteration = 1; iteration < iterations; iteration++) {
                u = this.hmacSha512(password, u);

                // Step 5: XOR U2 with previous result
                for (let i = 0; i < hashLength; i++) {
                    block[i] ^= u[i];
                }

                // Step 6: Append result to derived key
                derivedKey.set(block.subarray(0, Math.min(hashLength, keyLength)), (blockIndex - 1) * hashLength);
            }
        }

        return derivedKey;
    }

    encrypt(plaintext) {
        const iv = EonaCatCipher.generateRandomBytes(this.ivSize);
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const ciphertext = new Uint8Array(plaintextBytes.length);

        const cipher = new EonaCatCrypto(this.derivedKey, iv, this.blockSize, this.rounds);
        cipher.generate(plaintextBytes, ciphertext, true);

        // Combine IV and ciphertext
        const result = new Uint8Array(this.ivSize + ciphertext.length);
        result.set(iv, 0);
        result.set(ciphertext, this.ivSize);

        // Generate HMAC for integrity check
        const hmac = this.generateHMAC(result);

        // Combine result and HMAC
        const finalResult = new Uint8Array(result.length + hmac.length);
        finalResult.set(result, 0);
        finalResult.set(hmac, result.length);

        return finalResult;
    }

    decrypt(ciphertextWithHMAC) {
        const hmacOffset = ciphertextWithHMAC.length - 32; // HMAC length (SHA256)

        // Separate HMAC from the ciphertext
        const providedHMAC = ciphertextWithHMAC.subarray(hmacOffset, ciphertextWithHMAC.length);

        const ciphertext = ciphertextWithHMAC.subarray(0, hmacOffset);

        // Verify HMAC before decrypting
        const calculatedHMAC = this.generateHMAC(ciphertext);
        if (!this.areEqual(providedHMAC, calculatedHMAC)) {
            throw new Error("EonaCatCipher: HMAC validation failed. Data may have been tampered with.");
        }

        // Extract IV
        const iv = ciphertext.subarray(0, this.ivSize);

        // Extract encrypted data
        const encryptedData = ciphertext.subarray(this.ivSize);

        // Decrypt
        const decryptedData = new Uint8Array(encryptedData.length);
        const cipher = new EonaCatCrypto(this.derivedKey, iv, this.blockSize, this.rounds);
        cipher.generate(encryptedData, decryptedData, false);

        return new TextDecoder().decode(decryptedData);
    }

    generateHMAC(data) {
        return this.hmacSha256(this.hmacKey, data);
    }

    hmacSha512(key, data) {
        const hmac = new HMAC(key, "SHA-512");
        return hmac.compute(data);
    }

    hmacSha256(key, data) {
        const hmac = new HMAC(key, "SHA-256");
        return hmac.compute(data);
    }

    areEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}

class EonaCatCrypto {
    constructor(keyWithSalt, nonce, blockSize, rounds) {
        this.rounds = rounds;
        this.blockSize = blockSize > 0 ? blockSize : 128;

        this.key = new Uint32Array(keyWithSalt.length / 4);
        this.key.set(new Uint32Array(keyWithSalt.buffer));

        this.nonce = new Uint32Array(nonce.length / 4);
        this.nonce.set(new Uint32Array(nonce.buffer));

        this.state = new BigUint64Array(this.blockSize / 4);
        this.blockCounter = 0;
    }

    generateBlock(output) {
        // Initialize state using a combined operation
        for (let i = 0; i < this.state.length; i++) {
            this.state[i] = (this.key[i % this.key.length] ^ this.nonce[i % this.nonce.length]) + BigInt(i) * BigInt(0x5DEECE66D);
        }

        // Mix the states according to the rounds
        for (let round = 0; round < this.rounds; round++) {
            for (let i = 0; i < this.state.length; i++) {
                this.state[i] = (this.state[i] + BigInt(round)) ^ (BigInt(round) * BigInt(0x5DEECE66D)) + BigInt(i + this.blockCounter);
            }
        }

        // Output block
        output.set(new Uint8Array(this.state.buffer));
        this.blockCounter++;
    }

    generate(input, output, encrypt) {
        const totalBlocks = Math.ceil(input.length / this.blockSize);

        for (let blockIndex = 0; blockIndex < totalBlocks; blockIndex++) {
            const inputOffset = blockIndex * this.blockSize;
            const outputOffset = blockIndex * this.blockSize;
            const block = new Uint8Array(this.blockSize);

            // Generate a block based on the input
            this.generateBlock(block);

            // Perform XOR for encryption or decryption
            for (let i = 0; i < block.length && inputOffset + i < input.length; i++) {
                output[outputOffset + i] = input[inputOffset + i] ^ block[i];
            }
        }
    }
}

class HMAC {
    constructor(key, algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    compute(data) {
        const cryptoKey = crypto.subtle.importKey(
            "raw",
            this.key,
            { name: "HMAC", hash: { name: this.algorithm } },
            false,
            ["sign", "verify"]
        );

        return crypto.subtle.sign("HMAC", cryptoKey, data).then(signature => new Uint8Array(signature));
    }
}

// Usage Example
(async () => {
    const password = "securePassword123!@#$";
    const plaintext = "Thank you for using EonaCatCipher!";

    console.log(`Encrypting '${plaintext}' with password '${password}' (we do this 5 times)`);
    console.log("================");

    for (let i = 0; i < 5; i++) {
        console.log(`Encryption round ${i + 1}: `);
        console.log("================");

        const cipher = new EonaCatCipher(password);
        const encrypted = await cipher.encrypt(plaintext);

        console.log("Encrypted (byte array): " + Array.from(encrypted).join(', '));

        const decrypted = await cipher.decrypt(encrypted);

        console.log("Decrypted: " + decrypted);
        console.log("================");
    }
})();
