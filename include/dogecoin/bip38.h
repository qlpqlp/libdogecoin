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

#ifndef __LIBDOGECOIN_BIP38_H__
#define __LIBDOGECOIN_BIP38_H__

#include <stdint.h>
#include <stddef.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>

LIBDOGECOIN_BEGIN_DECL

/* BIP38 constants (non-EC multiplied keys: 0x01 0x42 + flag + addresshash + ciphertext) */
#define BIP38_MAGIC_BYTE 0x01
/** Second byte: non-EC multiplied key type (BIP38). */
#define BIP38_TYPE_NON_EC 0x42
/** Flag byte: top bits reserved per BIP38; bit 5 = compressed pubkey. */
#define BIP38_FLAG_BASE 0xC0
#define BIP38_SCRYPT_N 16384
#define BIP38_SCRYPT_R 8
#define BIP38_SCRYPT_P 8
#define BIP38_SCRYPT_KEYSIZE 64
#define BIP38_SCRYPT_SALTSIZE 4
#define BIP38_SCRYPT_DERIVED_SIZE 64

/* BIP38 encrypted key length */
#define BIP38_ENCRYPTED_KEY_LENGTH 58

/* BIP38 address hash length */
#define BIP38_ADDRESS_HASH_LENGTH 4

/* BIP38 compressed flag */
#define BIP38_COMPRESSED_FLAG 0x20

/* BIP38 lot/sequence flag */
#define BIP38_LOT_SEQUENCE_FLAG 0x04

/* BIP38 has lot/sequence flag */
#define BIP38_HAS_LOT_SEQUENCE_FLAG 0x08

/* EC multiplied key type (second byte of payload). */
#define BIP38_TYPE_EC_MULTIPLIED 0x43

/* BIP38 encrypted key structure */
typedef struct {
    uint8_t magic_byte;
    uint8_t flag_byte;
    uint8_t address_hash[BIP38_ADDRESS_HASH_LENGTH];
    uint8_t encrypted_key[32];
    uint8_t checksum[4];
} dogecoin_bip38_encrypted_key;

/* BIP38 lot/sequence structure */
typedef struct {
    uint8_t lot[4];
    uint8_t sequence[4];
} dogecoin_bip38_lot_sequence;

/* BIP38 EC multiplied structure */
typedef struct {
    uint8_t owner_entropy[8];
    uint8_t encrypted_part1[8];
    uint8_t encrypted_part2[16];
} dogecoin_bip38_ec_multiplied;

/*
 * Function declarations
 */

/* Encrypt a private key using BIP38 */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size
);

/* Decrypt a BIP38 encrypted private key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

/* Encrypt a private key using BIP38 with lot/sequence */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_encrypt_with_lot_sequence(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    uint32_t lot,
    uint32_t sequence,
    char* encrypted_key_out,
    size_t* encrypted_key_size
);

/* Decrypt a BIP38 encrypted private key with lot/sequence */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Check if a string is a valid BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key);

/* Get the address hash from a BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_get_address_hash(
    const char* encrypted_key,
    uint8_t* address_hash_out
);

/* Verify the address hash matches the given address */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_verify_address_hash(
    const char* encrypted_key,
    const char* address
);

/* Get the flag byte from a BIP38 encrypted key */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_get_flag_byte(
    const char* encrypted_key,
    uint8_t* flag_byte_out
);

/* Check if a BIP38 encrypted key is compressed */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_compressed(const char* encrypted_key);

/* Check if a BIP38 encrypted key has lot/sequence */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_has_lot_sequence(const char* encrypted_key);

/* Check if a BIP38 encrypted key is EC multiplied */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_is_ec_multiplied(const char* encrypted_key);

/* Generate a random lot and sequence for BIP38 */
LIBDOGECOIN_API void dogecoin_bip38_generate_lot_sequence(
    uint32_t* lot_out,
    uint32_t* sequence_out
);

/* Convert a private key to WIF format */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_private_key_to_wif(
    const uint8_t* private_key,
    const dogecoin_chainparams* chain,
    dogecoin_bool compressed,
    char* wif_out,
    size_t* wif_size
);

/* Convert a WIF private key to raw format */
LIBDOGECOIN_API dogecoin_bool dogecoin_bip38_wif_to_private_key(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_BIP38_H__
