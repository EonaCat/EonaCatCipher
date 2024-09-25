require 'openssl'
require 'securerandom'

class EonaCatCipher
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

  def initialize(password, salt_size = DEFAULT_SALT_SIZE, iv_size = DEFAULT_IV_SIZE, key_size = DEFAULT_KEY_SIZE, rounds = DEFAULT_ROUNDS, block_size = DEFAULT_BLOCK_SIZE)
    raise ArgumentError, 'EonaCatCipher: Password cannot be null or empty.' if password.nil? || password.empty?

    @iv_size = iv_size
    @key_size = key_size
    @rounds = rounds
    @block_size = block_size

    # Derive encryption key and HMAC key
    @derived_key, @hmac_key = derive_key_and_hmac(password, salt_size)
  end

  def encrypt(plaintext)
    iv = generate_random_bytes(@iv_size)
    plaintext_bytes = plaintext.encode('UTF-8')
    ciphertext = Array.new(plaintext_bytes.bytesize, 0)

    cipher = EonaCatCrypto.new(@derived_key, iv, @block_size, @rounds)
    cipher.generate(plaintext_bytes.bytes, ciphertext, true)

    # Combine IV and ciphertext
    result = iv + ciphertext.pack('C*')

    # Generate HMAC for integrity check
    hmac = generate_hmac(result)

    # Combine result and HMAC
    final_result = result + hmac
    final_result
  end

  def decrypt(ciphertext_with_hmac)
    hmac_offset = ciphertext_with_hmac.bytesize - HMAC_KEY_SIZE

    # Separate HMAC from the ciphertext
    provided_hmac = ciphertext_with_hmac[hmac_offset, HMAC_KEY_SIZE]
    ciphertext = ciphertext_with_hmac[0, hmac_offset]

    # Verify HMAC before decrypting
    calculated_hmac = generate_hmac(ciphertext)
    raise 'EonaCatCipher: HMAC validation failed. Data may have been tampered with.' unless secure_compare(provided_hmac, calculated_hmac)

    # Extract IV
    iv = ciphertext[0, @iv_size]

    # Extract encrypted data
    encrypted_data = ciphertext[@iv_size, ciphertext.bytesize - @iv_size]

    # Decrypt
    decrypted_data = Array.new(encrypted_data.bytesize, 0)
    cipher = EonaCatCrypto.new(@derived_key, iv, @block_size, @rounds)
    cipher.generate(encrypted_data.bytes, decrypted_data, false)

    decrypted_data.pack('C*').force_encoding('UTF-8')
  end

  private

  def generate_random_bytes(size)
    SecureRandom.random_bytes(size)
  end

  def derive_key_and_hmac(password, salt_size)
    salt = generate_random_bytes(salt_size)
    encryption_key = pbkdf2(password, salt, @key_size, @rounds)

    # Derive separate key for HMAC
    hmac_key = pbkdf2(password, salt, HMAC_KEY_SIZE, @rounds)

    key_with_salt = salt + encryption_key
    [key_with_salt, hmac_key]
  end

  def pbkdf2(password, salt, key_length, iterations)
    hmac = OpenSSL::Digest::SHA512.new
    derived_key = []

    block_size = hmac.digest_length
    blocks_needed = (key_length.to_f / block_size).ceil

    blocks_needed.times do |block_index|
      block_index += 1  # PBKDF2 block indexing starts at 1
      u = OpenSSL::HMAC.digest(hmac, password, salt + [block_index].pack('N'))
      derived_key.concat(u.bytes)

      (iterations - 1).times do
        u = OpenSSL::HMAC.digest(hmac, password, u)
        derived_key[-block_size, block_size].each_index do |i|
          derived_key[-block_size + i] ^= u.bytes[i]
        end
      end
    end

    derived_key[0, key_length]
  end

  def generate_hmac(data)
    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @hmac_key, data)
    hmac.bytes
  end

  def secure_compare(a, b)
    return false if a.bytesize != b.bytesize

    # Use `each_byte` for a timing-safe comparison
    res = 0
    a.each_byte.with_index do |byte, i|
      res |= byte ^ b.getbyte(i)
    end
    res == 0
  end
end

class EonaCatCrypto
  SECRET_SAUCE = 0x5DEECE66D

  def initialize(key_with_salt, nonce, block_size, rounds)
    @rounds = rounds
    @block_size = block_size / 4 > 0 ? block_size : 128

    @key = key_with_salt.unpack('N*')
    @nonce = nonce.unpack('N*')
    @state = Array.new(@block_size / 4, 0)
    @block_counter = 0
  end

  def generate(input, output, encrypt)
    total_blocks = (input.length + @block_size - 1) / @block_size

    total_blocks.times do |block_index|
      input_offset = block_index * @block_size
      output_offset = block_index * @block_size
      block = Array.new(@block_size, 0)

      generate_block(block)

      (0...block.size).each do |i|
        if input_offset + i < input.size
          output[output_offset + i] = input[input_offset + i] ^ block[i]
        end
      end
    end
  end

  private

  def generate_block(output)
    @state.each_index do |i|
      @state[i] = (@key[i % @key.size] ^ @nonce[i % @nonce.size]) + (i * SECRET_SAUCE)
    end

    @rounds.times do |round|
      @state.each_index do |i|
        @state[i] = ((@state[i] + round) ^ (round * SECRET_SAUCE) + (i + @block_counter)).to_i
      end
    end

    output.replace(@state.pack('Q*'))
    @block_counter += 1
  end
end

# Example Usage
if __FILE__ == $0
  password = "securePassword123!@#$"
  plaintext = "Thank you for using EonaCatCipher!"

  puts "Encrypting '#{plaintext}' with password '#{password}' (we do this 5 times)"
  puts "================"

  5.times do |i|
    puts "Encryption round #{i + 1}: "
    puts "================"

    cipher = EonaCatCipher.new(password)
    encrypted = cipher.encrypt(plaintext)

    puts "Encrypted (byte array): #{encrypted.unpack1('H*')}"

    decrypted = cipher.decrypt(encrypted)

    puts "Decrypted: #{decrypted}"
    puts "================"
  end
end
