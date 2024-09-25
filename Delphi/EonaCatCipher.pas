unit EonaCatCipher;

interface

uses
  SysUtils, Classes, Hash, HMAC, Cryptography, Generics.Collections;

{*
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
 *}

type
  TEonaCatCipher = class(TObject)
  private
    const
      DEFAULT_SALT_SIZE = 2048;  // Salt size for key derivation
      DEFAULT_IV_SIZE = 2048;    // IV size (2048 bits)
      DEFAULT_KEY_SIZE = 2048;   // Key size (2048 bits)
      DEFAULT_ROUNDS = 2048;     // Rounds
      DEFAULT_BLOCK_SIZE = 8192; // 8KB
      HMAC_KEY_SIZE = 32;        // Key size for HMAC (256 bits)

    var
      _derivedKey: TBytes; // Derived encryption key
      _hmacKey: TBytes;    // HMAC key
      _ivSize: Integer;    // IV size
      _keySize: Integer;   // Key size
      _rounds: Integer;    // Number of rounds for key derivation
      _blockSize: Integer; // The size of the block that is created

    function GenerateRandomBytes(size: Integer): TBytes;
    function DeriveKeyAndHMAC(password: string; saltSize: Integer): TBytes;
    function PBKDF2(password: string; salt: TBytes; keyLength: Integer; iterations: Integer): TBytes;
    function GenerateHMAC(data: TBytes): TBytes;
    function AreEqual(a, b: TBytes): Boolean;

  public
    constructor Create(password: string; saltSize: Integer = DEFAULT_SALT_SIZE; 
      ivSize: Integer = DEFAULT_IV_SIZE; keySize: Integer = DEFAULT_KEY_SIZE; 
      rounds: Integer = DEFAULT_ROUNDS; blockSize: Integer = DEFAULT_BLOCK_SIZE);
    destructor Destroy; override;

    function Encrypt(plaintext: string): TBytes;
    function Decrypt(ciphertextWithHMAC: TBytes): string;

  end;

implementation

constructor TEonaCatCipher.Create(password: string; saltSize: Integer; 
  ivSize: Integer; keySize: Integer; rounds: Integer; blockSize: Integer);
begin
  inherited Create;

  if password = '' then
    raise Exception.Create('EonaCatCipher: Password cannot be null or empty.');

  _ivSize := ivSize;
  _keySize := keySize;
  _rounds := rounds;
  _blockSize := blockSize;

  // Derive encryption key and HMAC key
  (_derivedKey, _hmacKey) := DeriveKeyAndHMAC(password, saltSize);
end;

destructor TEonaCatCipher.Destroy;
begin
  if Length(_derivedKey) > 0 then
    FillChar(_derivedKey[0], Length(_derivedKey), 0);

  if Length(_hmacKey) > 0 then
    FillChar(_hmacKey[0], Length(_hmacKey), 0);

  inherited Destroy;
end;

function TEonaCatCipher.GenerateRandomBytes(size: Integer): TBytes;
begin
  SetLength(Result, size);
  RandomBytes(Result);
end;

function TEonaCatCipher.DeriveKeyAndHMAC(password: string; saltSize: Integer): TBytes;
var
  salt, encryptionKey, hmacKey: TBytes;
begin
  salt := GenerateRandomBytes(saltSize);
  encryptionKey := PBKDF2(password, salt, _keySize, _rounds);
  hmacKey := PBKDF2(password, salt, HMAC_KEY_SIZE, _rounds);

  SetLength(Result, saltSize + Length(encryptionKey));
  Move(salt[0], Result[0], saltSize);
  Move(encryptionKey[0], Result[saltSize], Length(encryptionKey));

  // Combine encryptionKey and hmacKey if needed for further processing
end;

function TEonaCatCipher.PBKDF2(password: string; salt: TBytes; keyLength: Integer; iterations: Integer): TBytes;
var
  hmac: IHMAC;
  hashLength, requiredBytes, blocksNeeded, blockIndex: Integer;
  derivedKey, block: TBytes;
  currentBlock: TBytes;
  u: TBytes;
begin
  hmac := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA512);
  hmac.Key := TEncoding.UTF8.GetBytes(password);
  hashLength := hmac.HashSize div 8;
  requiredBytes := keyLength;
  blocksNeeded := Ceil(requiredBytes / hashLength);

  SetLength(derivedKey, requiredBytes);
  SetLength(block, hashLength);

  for blockIndex := 1 to blocksNeeded do
  begin
    SetLength(currentBlock, Length(salt) + SizeOf(Integer));
    Move(salt[0], currentBlock[0], Length(salt));
    Move(blockIndex, currentBlock[Length(salt)], SizeOf(Integer));

    // U1 = HMAC(password, salt + blockIndex)
    u := hmac.ComputeHash(currentBlock);
    Move(u[0], block[0], hashLength);
    Move(u[0], derivedKey[(blockIndex - 1) * hashLength], Min(hashLength, requiredBytes));

    // Iterations
    for var iteration := 1 to iterations - 1 do
    begin
      // U2 = HMAC(password, U1)
      u := hmac.ComputeHash(u);
      for var i := 0 to hashLength - 1 do
        block[i] := block[i] xor u[i];

      // Append result to derived key
      Move(block[0], derivedKey[(blockIndex - 1) * hashLength], Min(hashLength, requiredBytes));
    end;
  end;

  Result := derivedKey;
end;

function TEonaCatCipher.Encrypt(plaintext: string): TBytes;
var
  iv, plaintextBytes: TBytes;
  ciphertext: TBytes;
  result: TBytes;
  hmac: TBytes;
begin
  iv := GenerateRandomBytes(_ivSize);
  plaintextBytes := TEncoding.UTF8.GetBytes(plaintext);
  SetLength(ciphertext, Length(plaintextBytes));

  // Note: Implement the EonaCatCrypto class and its Generate method for encryption here
  // using a similar approach to the C# version

  // Combine IV and ciphertext
  SetLength(result, _ivSize + Length(ciphertext));
  Move(iv[0], result[0], _ivSize);
  Move(ciphertext[0], result[_ivSize], Length(ciphertext));

  // Generate HMAC for integrity check
  hmac := GenerateHMAC(result);

  // Combine result and HMAC
  SetLength(Result, Length(result) + Length(hmac));
  Move(result[0], Result[0], Length(result));
  Move(hmac[0], Result[Length(result)], Length(hmac));
end;

function TEonaCatCipher.Decrypt(ciphertextWithHMAC: TBytes): string;
var
  hmacOffset: Integer;
  providedHMAC, ciphertext: TBytes;
  calculatedHMAC: TBytes;
  iv: TBytes;
  encryptedData: TBytes;
  decryptedData: TBytes;
begin
  hmacOffset := Length(ciphertextWithHMAC) - HMAC_KEY_SIZE;

  // Separate HMAC from the ciphertext
  SetLength(providedHMAC, HMAC_KEY_SIZE);
  Move(ciphertextWithHMAC[hmacOffset], providedHMAC[0], HMAC_KEY_SIZE);
  SetLength(ciphertext, hmacOffset);
  Move(ciphertextWithHMAC[0], ciphertext[0], hmacOffset);

  // Verify HMAC before decrypting
  calculatedHMAC := GenerateHMAC(ciphertext);
  if not AreEqual(providedHMAC, calculatedHMAC) then
    raise Exception.Create('EonaCatCipher: HMAC validation failed. Data may have been tampered with.');

  // Extract IV
  SetLength(iv, _ivSize);
  Move(ciphertext[0], iv[0], _ivSize);

  // Extract encrypted data
  SetLength(encryptedData, Length(ciphertext) - _ivSize);
  Move(ciphertext[_ivSize], encryptedData[0], Length(encryptedData));

  // Decrypt
  // Note: Implement the EonaCatCrypto class and its Generate method for decryption here
  // using a similar approach to the C# version

  Result := TEncoding.UTF8.GetString(decryptedData);
end;

function TEonaCatCipher.GenerateHMAC(data: TBytes): TBytes;
var
  hmac: IHMAC;
begin
  hmac := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA256);
  hmac.Key := _hmacKey;
  Result := hmac.ComputeHash(data);
end;

function TEonaCatCipher.AreEqual(a, b: TBytes): Boolean;
var
  i: Integer;
begin
  Result := Length(a) = Length(b);
  if Result then
  begin
    for i := 0 to High(a) do
      if a[i] <> b[i] then
      begin
        Result := False;
        Break;
      end;
  end;
end;

end.
