/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <dogecoin/bip38.h>
#include <dogecoin/base58.h>
#include <dogecoin/sha2.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/aes.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/random.h>
#include <dogecoin/mem.h>
#include <dogecoin/utils.h>
#include <dogecoin/key.h>
#include <string.h>
#include <stdio.h>

/* Internal function to calculate address hash */
static dogecoin_bool calculate_address_hash(const char* address, uint8_t* address_hash_out) {
    if (!address || !address_hash_out) return false;
    
    uint256_t sha256_hash;
    uint160_t ripemd160_hash;
    
    dogecoin_sha256((uint8_t*)address, strlen(address), (uint8_t*)&sha256_hash);
    dogecoin_rmd160((uint8_t*)&sha256_hash, sizeof(sha256_hash), address_hash_out);
    
    return true;
}

/* Internal function to derive key from passphrase */
static dogecoin_bool derive_key_from_passphrase(
    const char* passphrase,
    const uint8_t* salt,
    size_t salt_len,
    uint8_t* derived_key
) {
    if (!passphrase || !salt || !derived_key) return false;
    
    return dogecoin_scrypt(
        (const uint8_t*)passphrase, strlen(passphrase),
        salt, salt_len,
        BIP38_SCRYPT_N, BIP38_SCRYPT_R, BIP38_SCRYPT_P,
        derived_key, BIP38_SCRYPT_DERIVED_SIZE
    );
}

/* Internal function to encrypt private key */
static dogecoin_bool encrypt_private_key(
    const uint8_t* private_key,
    const uint8_t* derived_key,
    const uint8_t* address_hash,
    dogecoin_bool compressed,
    uint8_t* encrypted_key_out
) {
    if (!private_key || !derived_key || !address_hash || !encrypted_key_out) return false;
    
    uint8_t key1[32], key2[32];
    memcpy(key1, derived_key, 32);
    memcpy(key2, derived_key + 32, 32);
    
    /* XOR private key with key1 */
    for (int i = 0; i < 32; i++) {
        encrypted_key_out[i] = private_key[i] ^ key1[i];
    }
    
    /* Encrypt with AES */
    dogecoin_aes_encrypt(encrypted_key_out, 32, key2, encrypted_key_out);
    
    return true;
}

/* Internal function to decrypt private key */
static dogecoin_bool decrypt_private_key(
    const uint8_t* encrypted_key,
    const uint8_t* derived_key,
    uint8_t* private_key_out
) {
    if (!encrypted_key || !derived_key || !private_key_out) return false;
    
    uint8_t key2[32];
    memcpy(key2, derived_key + 32, 32);
    
    /* Decrypt with AES */
    dogecoin_aes_decrypt(encrypted_key, 32, key2, private_key_out);
    
    /* XOR with key1 */
    uint8_t key1[32];
    memcpy(key1, derived_key, 32);
    for (int i = 0; i < 32; i++) {
        private_key_out[i] ^= key1[i];
    }
    
    return true;
}

/* Internal function to calculate checksum */
static void calculate_checksum(const uint8_t* data, size_t data_len, uint8_t* checksum_out) {
    uint256_t hash1, hash2;
    dogecoin_sha256(data, data_len, (uint8_t*)&hash1);
    dogecoin_sha256((uint8_t*)&hash1, sizeof(hash1), (uint8_t*)&hash2);
    memcpy(checksum_out, &hash2, 4);
}

/* Internal function to verify checksum */
static dogecoin_bool verify_checksum(const uint8_t* data, size_t data_len, const uint8_t* checksum) {
    uint8_t calculated_checksum[4];
    calculate_checksum(data, data_len, calculated_checksum);
    return memcmp(calculated_checksum, checksum, 4) == 0;
}

/* Encrypt a private key using BIP38 */
dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size
) {
    if (!private_key || !passphrase || !address || !encrypted_key_out || !encrypted_key_size) {
        return false;
    }
    
    if (*encrypted_key_size < BIP38_ENCRYPTED_KEY_LENGTH + 1) {
        return false;
    }
    
    /* Calculate address hash */
    uint8_t address_hash[BIP38_ADDRESS_HASH_LENGTH];
    if (!calculate_address_hash(address, address_hash)) {
        return false;
    }
    
    /* Generate random salt */
    uint8_t salt[BIP38_SCRYPT_SALTSIZE];
    dogecoin_random_bytes(salt, BIP38_SCRYPT_SALTSIZE, 1);
    
    /* Derive key from passphrase */
    uint8_t derived_key[BIP38_SCRYPT_DERIVED_SIZE];
    if (!derive_key_from_passphrase(passphrase, salt, BIP38_SCRYPT_SALTSIZE, derived_key)) {
        return false;
    }
    
    /* Encrypt private key */
    uint8_t encrypted_key[32];
    if (!encrypt_private_key(private_key, derived_key, address_hash, compressed, encrypted_key)) {
        return false;
    }
    
    /* Build encrypted key structure */
    dogecoin_bip38_encrypted_key bip38_key;
    bip38_key.magic_byte = BIP38_MAGIC_BYTE;
    bip38_key.flag_byte = BIP38_FLAG_BYTE | (compressed ? BIP38_COMPRESSED_FLAG : 0);
    memcpy(bip38_key.address_hash, address_hash, BIP38_ADDRESS_HASH_LENGTH);
    memcpy(bip38_key.encrypted_key, encrypted_key, 32);
    
    /* Calculate checksum */
    uint8_t data[38];
    data[0] = bip38_key.magic_byte;
    data[1] = bip38_key.flag_byte;
    memcpy(data + 2, bip38_key.address_hash, BIP38_ADDRESS_HASH_LENGTH);
    memcpy(data + 6, bip38_key.encrypted_key, 32);
    
    calculate_checksum(data, 38, bip38_key.checksum);
    
    /* Encode to base58 */
    uint8_t full_key[43];
    full_key[0] = bip38_key.magic_byte;
    full_key[1] = bip38_key.flag_byte;
    memcpy(full_key + 2, bip38_key.address_hash, BIP38_ADDRESS_HASH_LENGTH);
    memcpy(full_key + 6, bip38_key.encrypted_key, 32);
    memcpy(full_key + 38, bip38_key.checksum, 4);
    memcpy(full_key + 42, salt, 1); /* Only first byte of salt */
    
    size_t encoded_size = *encrypted_key_size;
    if (!dogecoin_base58_encode(encrypted_key_out, &encoded_size, full_key, 43)) {
        return false;
    }
    *encrypted_key_size = encoded_size;
    
    return true;
}

/* Decrypt a BIP38 encrypted private key */
dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
) {
    if (!encrypted_key || !passphrase || !private_key_out || !compressed_out) {
        return false;
    }
    
    /* Decode from base58 */
    uint8_t decoded_key[43];
    size_t decoded_len = 43;
    if (!dogecoin_base58_decode(decoded_key, &decoded_len, encrypted_key, strlen(encrypted_key))) {
        return false;
    }
    
    if (decoded_len != 43) {
        return false;
    }
    
    /* Verify magic byte */
    if (decoded_key[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    
    /* Verify flag byte */
    if (decoded_key[1] != BIP38_FLAG_BYTE) {
        return false;
    }
    
    /* Extract components */
    uint8_t address_hash[BIP38_ADDRESS_HASH_LENGTH];
    uint8_t encrypted_key_data[32];
    uint8_t checksum[4];
    uint8_t salt[BIP38_SCRYPT_SALTSIZE];
    
    memcpy(address_hash, decoded_key + 2, BIP38_ADDRESS_HASH_LENGTH);
    memcpy(encrypted_key_data, decoded_key + 6, 32);
    memcpy(checksum, decoded_key + 38, 4);
    salt[0] = decoded_key[42];
    salt[1] = 0;
    salt[2] = 0;
    salt[3] = 0;
    
    /* Verify checksum */
    if (!verify_checksum(decoded_key, 38, checksum)) {
        return false;
    }
    
    /* Derive key from passphrase */
    uint8_t derived_key[BIP38_SCRYPT_DERIVED_SIZE];
    if (!derive_key_from_passphrase(passphrase, salt, BIP38_SCRYPT_SALTSIZE, derived_key)) {
        return false;
    }
    
    /* Decrypt private key */
    if (!decrypt_private_key(encrypted_key_data, derived_key, private_key_out)) {
        return false;
    }
    
    /* Set compressed flag */
    *compressed_out = (decoded_key[1] & BIP38_COMPRESSED_FLAG) != 0;
    
    return true;
}

/* Check if a string is a valid BIP38 encrypted key */
dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key) {
    if (!encrypted_key) return false;
    
    /* Check length */
    if (strlen(encrypted_key) != BIP38_ENCRYPTED_KEY_LENGTH) {
        return false;
    }
    
    /* Try to decode */
    uint8_t decoded_key[43];
    size_t decoded_len = 43;
    if (!dogecoin_base58_decode(decoded_key, &decoded_len, encrypted_key, strlen(encrypted_key))) {
        return false;
    }
    
    if (decoded_len != 43) {
        return false;
    }
    
    /* Check magic byte */
    if (decoded_key[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    
    /* Check flag byte */
    if (decoded_key[1] != BIP38_FLAG_BYTE) {
        return false;
    }
    
    /* Verify checksum */
    uint8_t checksum[4];
    memcpy(checksum, decoded_key + 38, 4);
    return verify_checksum(decoded_key, 38, checksum);
}

/* Get the address hash from a BIP38 encrypted key */
dogecoin_bool dogecoin_bip38_get_address_hash(
    const char* encrypted_key,
    uint8_t* address_hash_out
) {
    if (!encrypted_key || !address_hash_out) return false;
    
    uint8_t decoded_key[43];
    size_t decoded_len = 43;
    if (!dogecoin_base58_decode(decoded_key, &decoded_len, encrypted_key, strlen(encrypted_key))) {
        return false;
    }
    
    if (decoded_len != 43) {
        return false;
    }
    
    memcpy(address_hash_out, decoded_key + 2, BIP38_ADDRESS_HASH_LENGTH);
    return true;
}

/* Verify the address hash matches the given address */
dogecoin_bool dogecoin_bip38_verify_address_hash(
    const char* encrypted_key,
    const char* address
) {
    if (!encrypted_key || !address) return false;
    
    uint8_t address_hash[BIP38_ADDRESS_HASH_LENGTH];
    uint8_t calculated_hash[BIP38_ADDRESS_HASH_LENGTH];
    
    if (!dogecoin_bip38_get_address_hash(encrypted_key, address_hash)) {
        return false;
    }
    
    if (!calculate_address_hash(address, calculated_hash)) {
        return false;
    }
    
    return memcmp(address_hash, calculated_hash, BIP38_ADDRESS_HASH_LENGTH) == 0;
}

/* Get the flag byte from a BIP38 encrypted key */
dogecoin_bool dogecoin_bip38_get_flag_byte(
    const char* encrypted_key,
    uint8_t* flag_byte_out
) {
    if (!encrypted_key || !flag_byte_out) return false;
    
    uint8_t decoded_key[43];
    size_t decoded_len = 43;
    if (!dogecoin_base58_decode(decoded_key, &decoded_len, encrypted_key, strlen(encrypted_key))) {
        return false;
    }
    
    if (decoded_len != 43) {
        return false;
    }
    
    *flag_byte_out = decoded_key[1];
    return true;
}

/* Check if a BIP38 encrypted key is compressed */
dogecoin_bool dogecoin_bip38_is_compressed(const char* encrypted_key) {
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    
    return (flag_byte & BIP38_COMPRESSED_FLAG) != 0;
}

/* Check if a BIP38 encrypted key has lot/sequence */
dogecoin_bool dogecoin_bip38_has_lot_sequence(const char* encrypted_key) {
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    
    return (flag_byte & BIP38_LOT_SEQUENCE_FLAG) != 0;
}

/* Check if a BIP38 encrypted key is EC multiplied */
dogecoin_bool dogecoin_bip38_is_ec_multiplied(const char* encrypted_key) {
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    
    return (flag_byte & BIP38_HAS_LOT_SEQUENCE_FLAG) != 0;
}

/* Generate a random lot and sequence for BIP38 */
void dogecoin_bip38_generate_lot_sequence(
    uint32_t* lot_out,
    uint32_t* sequence_out
) {
    if (!lot_out || !sequence_out) return;
    
    dogecoin_random_bytes((uint8_t*)lot_out, 4, 1);
    dogecoin_random_bytes((uint8_t*)sequence_out, 4, 1);
    
    /* Ensure lot is not zero */
    if (*lot_out == 0) {
        *lot_out = 1;
    }
}

/* Convert a private key to WIF format */
dogecoin_bool dogecoin_bip38_private_key_to_wif(
    const uint8_t* private_key,
    const dogecoin_chainparams* chain,
    dogecoin_bool compressed,
    char* wif_out,
    size_t* wif_size
) {
    if (!private_key || !chain || !wif_out || !wif_size) {
        return false;
    }
    
    dogecoin_key key;
    memcpy(key.privkey, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    
    dogecoin_privkey_encode_wif(&key, chain, wif_out, wif_size);
    return true;
}

/* Convert a WIF private key to raw format */
dogecoin_bool dogecoin_bip38_wif_to_private_key(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
) {
    if (!wif || !chain || !private_key_out || !compressed_out) {
        return false;
    }
    
    dogecoin_key key;
    if (!dogecoin_privkey_decode_wif(wif, chain, &key)) {
        return false;
    }
    
    memcpy(private_key_out, key.privkey, DOGECOIN_ECKEY_PKEY_LENGTH);
    *compressed_out = true; /* Assume compressed for now */
    
    return true;
}

/* Placeholder implementations for lot/sequence functions */
dogecoin_bool dogecoin_bip38_encrypt_with_lot_sequence(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    uint32_t lot,
    uint32_t sequence,
    char* encrypted_key_out,
    size_t* encrypted_key_size
) {
    /* For now, just use the basic encryption */
    return dogecoin_bip38_encrypt(private_key, passphrase, address, compressed, encrypted_key_out, encrypted_key_size);
}

dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
) {
    /* For now, just use the basic decryption */
    if (lot_out) *lot_out = 0;
    if (sequence_out) *sequence_out = 0;
    return dogecoin_bip38_decrypt(encrypted_key, passphrase, private_key_out, compressed_out);
}
