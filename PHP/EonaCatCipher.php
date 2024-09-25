<?php

class EonaCatCipher {
    private const DEFAULT_SALT_SIZE = 2048;  // Salt size for key derivation
    private const DEFAULT_IV_SIZE = 2048;    // IV size (16384 bits)
    private const DEFAULT_KEY_SIZE = 2048;   // Key size (16384 bits)
    private const DEFAULT_ROUNDS = 2048;     // Rounds
    private const DEFAULT_BLOCK_SIZE = 8192; // 8kb
    private const HMAC_KEY_SIZE = 32;        // Key size for HMAC (256 bits)

    private $derivedKey; // Derived encryption key
    private $hmacKey;    // HMAC key
    private $ivSize;     // IV size
    private $keySize;    // Key size
    private $rounds;     // Number of rounds for key derivation
    private $blockSize;  // The size of the block that is created

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

    public function __construct($password, $saltSize = self::DEFAULT_SALT_SIZE, $ivSize = self::DEFAULT_IV_SIZE, $keySize = self::DEFAULT_KEY_SIZE, $rounds = self::DEFAULT_ROUNDS, $blockSize = self::DEFAULT_BLOCK_SIZE) {
        if (empty($password)) {
            throw new InvalidArgumentException("EonaCatCipher: Password cannot be null or empty.");
        }

        $this->ivSize = $ivSize;
        $this->keySize = $keySize;
        $this->rounds = $rounds;
        $this->blockSize = $blockSize;

        // Derive encryption key and HMAC key
        list($this->derivedKey, $this->hmacKey) = $this->deriveKeyAndHMAC($password, $saltSize);
    }

    private static function generateRandomBytes($size) {
        return random_bytes($size);
    }

    private function deriveKeyAndHMAC($password, $saltSize) {
        $salt = self::generateRandomBytes($saltSize);
        $encryptionKey = $this->pbkdf2($password, $salt, $this->keySize, $this->rounds);

        // Derive separate key for HMAC
        $hmacKey = $this->pbkdf2($password, $salt, self::HMAC_KEY_SIZE, $this->rounds);

        $keyWithSalt = $salt . $encryptionKey;

        return [$keyWithSalt, $hmacKey];
    }

    private function pbkdf2($password, $salt, $keyLength, $iterations) {
        $hmac = hash_hmac('sha512', '', $password, true);
        $hashLength = strlen($hmac);
        $requiredBytes = $keyLength;
        $blocksNeeded = ceil($requiredBytes / $hashLength);

        $derivedKey = '';
        $block = '';

        for ($blockIndex = 1; $blockIndex <= $blocksNeeded; $blockIndex++) {
            $currentBlock = $salt . pack('N', $blockIndex);
            $u = hash_hmac('sha512', $currentBlock, $password, true);
            $block = $u;
            $derivedKey .= $u;

            for ($iteration = 1; $iteration < $iterations; $iteration++) {
                $u = hash_hmac('sha512', $u, $password, true);
                for ($i = 0; $i < $hashLength; $i++) {
                    $block[$i] ^= $u[$i];
                }
                $derivedKey .= $block;
            }
        }

        return substr($derivedKey, 0, $requiredBytes);
    }

    public function encrypt($plaintext) {
        $iv = self::generateRandomBytes($this->ivSize);
        $plaintextBytes = $plaintext;
        $ciphertext = str_repeat("\0", strlen($plaintextBytes));

        $cipher = new EonaCatCrypto($this->derivedKey, $iv, $this->blockSize, $this->rounds);
        $cipher->generate($plaintextBytes, $ciphertext, true);

        // Combine IV and ciphertext
        $result = $iv . $ciphertext;

        // Generate HMAC for integrity check
        $hmac = $this->generateHMAC($result);

        // Combine result and HMAC
        return $result . $hmac;
    }

    public function decrypt($ciphertextWithHMAC) {
        $hmacOffset = strlen($ciphertextWithHMAC) - self::HMAC_KEY_SIZE;

        // Separate HMAC from the ciphertext
        $providedHMAC = substr($ciphertextWithHMAC, $hmacOffset);
        $ciphertext = substr($ciphertextWithHMAC, 0, $hmacOffset);

        // Verify HMAC before decrypting
        $calculatedHMAC = $this->generateHMAC($ciphertext);
        if (!hash_equals($providedHMAC, $calculatedHMAC)) {
            throw new Exception("EonaCatCipher: HMAC validation failed. Data may have been tampered with.");
        }

        // Extract IV
        $iv = substr($ciphertext, 0, $this->ivSize);

        // Extract encrypted data
        $encryptedData = substr($ciphertext, $this->ivSize);

        // Decrypt
        $decryptedData = str_repeat("\0", strlen($encryptedData));
        $cipher = new EonaCatCrypto($this->derivedKey, $iv, $this->blockSize, $this->rounds);
        $cipher->generate($encryptedData, $decryptedData, false);

        return $decryptedData;
    }

    private function generateHMAC($data) {
        return hash_hmac('sha256', $data, $this->hmacKey, true);
    }

    public static function main() {
        $password = "securePassword123!@#$";
        $plaintext = "Thank you for using EonaCatCipher!";

        echo "Encrypting '$plaintext' with password '$password' (we do this 5 times)\n";
        echo "================\n";

        for ($i = 0; $i < 5; $i++) {
            echo "Encryption round " . ($i + 1) . ": \n";
            echo "================\n";

            $cipher = new EonaCatCipher($password);
            $encrypted = $cipher->encrypt($plaintext);

            echo "Encrypted (byte array): " . bin2hex($encrypted) . "\n";

            $decrypted = $cipher->decrypt($encrypted);

            echo "Decrypted: " . $decrypted . "\n";
            echo "================\n";
        }
    }
}

class EonaCatCrypto {
    private const SECRET_SAUCE = 0x5DEECE66D;
    private const UNSIGNED_INT = 0xFFFFFFFF;
    private $blockSize;
    private $rounds;
    private $state;
    private $key;
    private $nonce;
    private $blockCounter;

    public function __construct($keyWithSalt, $nonce, $blockSize, $rounds) {
        $this->rounds = $rounds;
        $this->blockSize = $blockSize / 4 > 0 ? $blockSize : 128;

        $this->key = array_values(unpack("N*", $keyWithSalt));
        $this->nonce = array_values(unpack("N*", $nonce));
        $this->state = array_fill(0, $this->blockSize / 4, 0);
        $this->blockCounter = 0;
    }

    private function generateBlock(&$output) {
        // Initialize state using a combined operation
        for ($i = 0; $i < count($this->state); $i++) {
            $this->state[$i] = ($this->key[$i % count($this->key)] ^ $this->nonce[$i % count($this->nonce)]) + ($i * self::SECRET_SAUCE);
        }

        // Mix the states according to the rounds
        for ($round = 0; $round < $this->rounds; $round++) {
            for ($i = 0; $i < count($this->state); $i++) {
                $this->state[$i] = (($this->state[$i] + $round) ^ ($round * self::SECRET_SAUCE) + ($i + $this->blockCounter)) & self::UNSIGNED_INT;
            }
        }

        // Output block
        $output = pack("N*", ...$this->state);
        $this->blockCounter++;
    }

    public function generate($input, &$output, $encrypt) {
        $totalBlocks = ceil(strlen($input) / $this->blockSize);

        for ($blockIndex = 0; $blockIndex < $totalBlocks; $blockIndex++) {
            $inputOffset = $blockIndex * $this->blockSize;
            $outputOffset = $blockIndex * $this->blockSize;
            $block = str_repeat("\0", $this->blockSize);

            // Generate a block based on the input
            $this->generateBlock($block);

            // Perform XOR for encryption or decryption
            for ($i = 0; $i < strlen($block) && $inputOffset + $i < strlen($input); $i++) {
                $output[$outputOffset + $i] = $input[$inputOffset + $i] ^ $block[$i];
            }
        }
    }
}

EonaCatCipher::main();

?>
