import os
import hashlib
import hmac
import struct
import base64

class EonaCatCipher:
    DEFAULT_SALT_SIZE = 2048;     # Salt size for key derivation
    DEFAULT_IV_SIZE = 2048;       # IV size (16384 bits)
    DEFAULT_KEY_SIZE = 2048;      # Key size (16384 bits)
    DEFAULT_ROUNDS = 2048;        # Rounds
    DEFAULT_BLOCK_SIZE = 8192;    # 8kb
    HMAC_KEY_SIZE = 32;           # Key size for HMAC (256 bits)

#/*
# * EonaCatCipher - Because security is key!
# * 
# * Copyright (c) 2024 EonaCat (Jeroen Saey)
# * 
# * https://eonacat.com/license
# * 
# *   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION 
# *                  OF SOFTWARE BY EONACAT (JEROEN SAEY)
# *
# * This software is provided "as is", without any express or implied warranty.
# * In no event shall the authors or copyright holders be liable for any claim,
# * damages or other liability, whether in an action of contract, tort or otherwise,
# * arising from, out of or in connection with the software or the use or other
# * dealings in the software.
# * 
# * You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# * copies of the Software, and permit persons to whom the Software is furnished 
# * to do so, subject to the following conditions:
# * 
# * 1. The above copyright notice and this permission notice shall be included in 
# *    all copies or substantial portions of the Software.
# * 
# * 2. The software must not be used for any unlawful purpose.
# * 
# * For any inquiries, please contact: eonacat@gmail.com
# */

    def __init__(self, password, salt_size=None, iv_size=None, key_size=None, rounds=None, block_size=None):
        if not password:
            raise ValueError("EonaCatCipher: Password cannot be null or empty.")

        self.salt_size = salt_size if salt_size is not None else self.DEFAULT_SALT_SIZE
        self.iv_size = iv_size if iv_size is not None else self.DEFAULT_IV_SIZE // 8  # Convert bits to bytes
        self.key_size = key_size if key_size is not None else self.DEFAULT_KEY_SIZE // 8  # Convert bits to bytes
        self.rounds = rounds if rounds is not None else self.DEFAULT_ROUNDS
        self.block_size = block_size if block_size is not None else self.DEFAULT_BLOCK_SIZE // 8  # Convert bits to bytes

        # Derive encryption key and HMAC key
        self.derived_key, self.hmac_key = self.derive_key_and_hmac(password)

    @staticmethod
    def generate_random_bytes(size):
        return os.urandom(size)

    def derive_key_and_hmac(self, password):
        salt = self.generate_random_bytes(self.salt_size)
        encryption_key = self.pbkdf2(password, salt, self.key_size, self.rounds)

        # Derive separate key for HMAC
        hmac_key = self.pbkdf2(password, salt, self.HMAC_KEY_SIZE, self.rounds)

        key_with_salt = salt + encryption_key

        return key_with_salt, hmac_key

    @staticmethod
    def pbkdf2(password, salt, key_length, iterations):
        # PBKDF2 using HMAC-SHA512
        hmac_sha512 = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations, dklen=key_length)
        return hmac_sha512

    def encrypt(self, plaintext):
        iv = self.generate_random_bytes(self.iv_size)
        plaintext_bytes = plaintext.encode()

        ciphertext = bytearray(len(plaintext_bytes))

        # Generate cipher
        cipher = EonaCatCrypto(self.derived_key, iv, self.block_size, self.rounds)
        cipher.generate(plaintext_bytes, ciphertext, True)

        # Combine IV and ciphertext
        result = iv + ciphertext

        # Generate HMAC for integrity check
        hmac = self.generate_hmac(result)

        # Combine result and HMAC
        final_result = result + hmac
        return final_result

    def decrypt(self, ciphertext_with_hmac):
        hmac_offset = len(ciphertext_with_hmac) - self.HMAC_KEY_SIZE

        # Separate HMAC from the ciphertext
        provided_hmac = ciphertext_with_hmac[hmac_offset:]
        ciphertext = ciphertext_with_hmac[:hmac_offset]

        # Verify HMAC before decrypting
        calculated_hmac = self.generate_hmac(ciphertext)
        if not self.are_equal(provided_hmac, calculated_hmac):
            raise ValueError("EonaCatCipher: HMAC validation failed. Data may have been tampered with.")

        # Extract IV
        iv = ciphertext[:self.iv_size]
        encrypted_data = ciphertext[self.iv_size:]

        # Decrypt
        decrypted_data = bytearray(len(encrypted_data))
        cipher = EonaCatCrypto(self.derived_key, iv, self.block_size, self.rounds)
        cipher.generate(encrypted_data, decrypted_data, False)

        return decrypted_data.decode()

    def generate_hmac(self, data):
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()

    @staticmethod
    def are_equal(a, b):
        return hmac.compare_digest(a, b)

class EonaCatCrypto:
    SECRET_SAUCE = 0x5DEECE66D

    def __init__(self, key_with_salt, nonce, block_size, rounds):
        self.rounds = rounds
        self.block_size = block_size // 4 > 0 and block_size // 4 or 128

        self.key = list(struct.unpack(f'>{len(key_with_salt) // 4}I', key_with_salt))
        self.nonce = list(struct.unpack(f'>{len(nonce) // 4}I', nonce))
        self.state = [0] * (self.block_size // 4)
        self.block_counter = 0

    def generate_block(self, output):
        # Initialize state using a combined operation
        for i in range(len(self.state)):
            self.state[i] = (self.key[i % len(self.key)] ^ self.nonce[i % len(self.nonce)]) + (i * self.SECRET_SAUCE)

        # Mix the states according to the rounds
        for round in range(self.rounds):
            for i in range(len(self.state)):
                self.state[i] = (self.state[i] + round) ^ (round * self.SECRET_SAUCE) + (i + self.block_counter)

        # Output block
        output.extend(self.state)
        self.block_counter += 1

    def generate(self, input_data, output, encrypt):
        total_blocks = (len(input_data) + self.block_size - 1) // self.block_size

        for block_index in range(total_blocks):
            input_offset = block_index * self.block_size
            block = bytearray(self.block_size)

            # Generate a block based on the input
            self.generate_block(block)

            # Perform XOR for encryption or decryption
            for i in range(len(block)):
                if input_offset + i < len(input_data):
                    output[input_offset + i] = input_data[input_offset + i] ^ block[i]

def main():
    password = "securePassword123!@#$"
    plaintext = "Thank you for using EonaCatCipher!"

    print(f"Encrypting '{plaintext}' with password '{password}' (we do this 5 times)")
    print("================")

    for i in range(5):
        print(f"Encryption round {i + 1}: ")
        print("================")

        cipher = EonaCatCipher(password)
        encrypted = cipher.encrypt(plaintext)

        print("Encrypted (byte array):", [b for b in encrypted])
        
        decrypted = cipher.decrypt(encrypted)
        print("Decrypted:", decrypted)
        print("================")

if __name__ == "__main__":
    main()
