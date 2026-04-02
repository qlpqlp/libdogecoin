/*
 * Copyright (c) 2024 The Dogecoin Foundation
 *
 * BIP38 non-EC multiplied keys per BIP-0038 (scrypt + AES-256-ECB, Base58Check).
 */

#include <dogecoin/bip38.h>
#include <dogecoin/base58.h>
#include <dogecoin/ctaes.h>
#include <dogecoin/scrypt_bip38.h>
#include <dogecoin/sha2.h>
#include <dogecoin/random.h>
#include <dogecoin/mem.h>
#include <dogecoin/key.h>

#include <string.h>
#include <stdio.h>

#define BIP38_PAYLOAD_LEN 39
/* dogecoin_base58_decode_check() requires data[] length >= strlen(base58 string). */
#define BIP38_BASE58_DECODE_BUFLEN 128

/* First four bytes of SHA256(SHA256(utf8 address)). */
static void bip38_address_hash(const char* address, uint8_t address_hash_out[4])
{
    uint8_t h[SHA256_DIGEST_LENGTH];
    sha256_raw((const uint8_t*)address, strlen(address), h);
    sha256_raw(h, SHA256_DIGEST_LENGTH, h);
    memcpy(address_hash_out, h, 4);
}

static dogecoin_bool bip38_derive_key(
    const char* passphrase,
    const uint8_t salt[4],
    uint8_t derived_key[64])
{
    return dogecoin_scrypt(
        (const uint8_t*)passphrase,
        strlen(passphrase),
        salt,
        4,
        BIP38_SCRYPT_N,
        BIP38_SCRYPT_R,
        BIP38_SCRYPT_P,
        derived_key,
        BIP38_SCRYPT_DERIVED_SIZE);
}

static void bip38_encrypt_halves(
    const uint8_t* private_key,
    const uint8_t* derived_64,
    uint8_t encrypted[32])
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    AES256_ctx ctx;
    AES256_init(&ctx, derivedhalf2);

    for (unsigned i = 0; i < 16; i++)
        block[i] = private_key[i] ^ derivedhalf1[i];
    AES256_encrypt(&ctx, 1, encrypted, block);

    for (unsigned i = 0; i < 16; i++)
        block[i] = private_key[16 + i] ^ derivedhalf1[16 + i];
    AES256_encrypt(&ctx, 1, encrypted + 16, block);
}

static void bip38_decrypt_halves(
    const uint8_t encrypted[32],
    const uint8_t* derived_64,
    uint8_t private_key_out[32])
{
    const uint8_t* derivedhalf1 = derived_64;
    const uint8_t* derivedhalf2 = derived_64 + 32;
    uint8_t block[16];
    AES256_ctx ctx;
    AES256_init(&ctx, derivedhalf2);

    AES256_decrypt(&ctx, 1, block, encrypted);
    for (unsigned i = 0; i < 16; i++)
        private_key_out[i] = block[i] ^ derivedhalf1[i];

    AES256_decrypt(&ctx, 1, block, encrypted + 16);
    for (unsigned i = 0; i < 16; i++)
        private_key_out[16 + i] = block[i] ^ derivedhalf1[16 + i];
}

dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size)
{
    if (!private_key || !passphrase || !address || !encrypted_key_out || !encrypted_key_size) {
        return false;
    }
    if (*encrypted_key_size < BIP38_ENCRYPTED_KEY_LENGTH + 1) {
        return false;
    }

    uint8_t address_hash[4];
    bip38_address_hash(address, address_hash);

    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    if (!bip38_derive_key(passphrase, address_hash, derived)) {
        return false;
    }

    uint8_t encrypted[32];
    bip38_encrypt_halves(private_key, derived, encrypted);
    dogecoin_mem_zero(derived, sizeof(derived));

    uint8_t payload[BIP38_PAYLOAD_LEN];
    payload[0] = BIP38_MAGIC_BYTE;
    payload[1] = BIP38_TYPE_NON_EC;
    payload[2] = (uint8_t)(BIP38_FLAG_BASE | (compressed ? BIP38_COMPRESSED_FLAG : 0));
    memcpy(payload + 3, address_hash, 4);
    memcpy(payload + 7, encrypted, 32);

    size_t encsz = *encrypted_key_size;
    size_t w = dogecoin_base58_encode_check(payload, BIP38_PAYLOAD_LEN, encrypted_key_out, encsz);
    if (w == 0) {
        return false;
    }
    *encrypted_key_size = w;
    return true;
}

dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    if (!encrypted_key || !passphrase || !private_key_out || !compressed_out) {
        return false;
    }

    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }

    if (decoded[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    if (decoded[1] != BIP38_TYPE_NON_EC) {
        return false;
    }

    uint8_t salt[4];
    memcpy(salt, decoded + 3, 4);
    const uint8_t* encrypted_body = decoded + 7;

    uint8_t derived[BIP38_SCRYPT_DERIVED_SIZE];
    if (!bip38_derive_key(passphrase, salt, derived)) {
        return false;
    }

    bip38_decrypt_halves(encrypted_body, derived, private_key_out);
    dogecoin_mem_zero(derived, sizeof(derived));

    *compressed_out = (decoded[2] & BIP38_COMPRESSED_FLAG) != 0;
    return true;
}

dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key)
{
    if (!encrypted_key) {
        return false;
    }

    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }

    if (decoded[0] != BIP38_MAGIC_BYTE) {
        return false;
    }
    if (decoded[1] != BIP38_TYPE_NON_EC) {
        return false;
    }
    return true;
}

dogecoin_bool dogecoin_bip38_get_address_hash(
    const char* encrypted_key,
    uint8_t* address_hash_out)
{
    if (!encrypted_key || !address_hash_out) {
        return false;
    }

    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }

    memcpy(address_hash_out, decoded + 3, 4);
    return true;
}

dogecoin_bool dogecoin_bip38_verify_address_hash(
    const char* encrypted_key,
    const char* address)
{
    if (!encrypted_key || !address) {
        return false;
    }

    uint8_t embedded[4];
    uint8_t calc[4];
    if (!dogecoin_bip38_get_address_hash(encrypted_key, embedded)) {
        return false;
    }
    bip38_address_hash(address, calc);
    return memcmp(embedded, calc, 4) == 0;
}

dogecoin_bool dogecoin_bip38_get_flag_byte(
    const char* encrypted_key,
    uint8_t* flag_byte_out)
{
    if (!encrypted_key || !flag_byte_out) {
        return false;
    }

    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }

    *flag_byte_out = decoded[2];
    return true;
}

dogecoin_bool dogecoin_bip38_is_compressed(const char* encrypted_key)
{
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    return (flag_byte & BIP38_COMPRESSED_FLAG) != 0;
}

dogecoin_bool dogecoin_bip38_has_lot_sequence(const char* encrypted_key)
{
    uint8_t flag_byte;
    if (!dogecoin_bip38_get_flag_byte(encrypted_key, &flag_byte)) {
        return false;
    }
    return (flag_byte & BIP38_LOT_SEQUENCE_FLAG) != 0;
}

dogecoin_bool dogecoin_bip38_is_ec_multiplied(const char* encrypted_key)
{
    if (!encrypted_key) {
        return false;
    }
    uint8_t decoded[BIP38_BASE58_DECODE_BUFLEN];
    size_t declen = dogecoin_base58_decode_check(encrypted_key, decoded, sizeof(decoded));
    if (declen != BIP38_PAYLOAD_LEN + 4) {
        return false;
    }
    return (decoded[0] == BIP38_MAGIC_BYTE && decoded[1] == BIP38_TYPE_EC_MULTIPLIED);
}

void dogecoin_bip38_generate_lot_sequence(
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    if (!lot_out || !sequence_out) {
        return;
    }

    dogecoin_random_bytes((uint8_t*)lot_out, 4, 1);
    dogecoin_random_bytes((uint8_t*)sequence_out, 4, 1);
    if (*lot_out == 0) {
        *lot_out = 1;
    }
}

dogecoin_bool dogecoin_bip38_private_key_to_wif(
    const uint8_t* private_key,
    const dogecoin_chainparams* chain,
    dogecoin_bool compressed,
    char* wif_out,
    size_t* wif_size)
{
    if (!private_key || !chain || !wif_out || !wif_size) {
        return false;
    }
    (void)compressed; /* WIF encoding in this library uses compressed keys (see dogecoin_privkey_encode_wif). */

    dogecoin_key key;
    memcpy(key.privkey, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    dogecoin_privkey_encode_wif(&key, chain, wif_out, wif_size);
    return true;
}

dogecoin_bool dogecoin_bip38_wif_to_private_key(
    const char* wif,
    const dogecoin_chainparams* chain,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out)
{
    if (!wif || !chain || !private_key_out || !compressed_out) {
        return false;
    }

    dogecoin_key key;
    if (!dogecoin_privkey_decode_wif(wif, chain, &key)) {
        return false;
    }

    memcpy(private_key_out, key.privkey, DOGECOIN_ECKEY_PKEY_LENGTH);
    /* dogecoin WIF encoding uses compressed keys (see dogecoin_privkey_encode_wif). */
    *compressed_out = true;
    return true;
}

dogecoin_bool dogecoin_bip38_encrypt_with_lot_sequence(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    uint32_t lot,
    uint32_t sequence,
    char* encrypted_key_out,
    size_t* encrypted_key_size)
{
    (void)lot;
    (void)sequence;
    return dogecoin_bip38_encrypt(private_key, passphrase, address, compressed, encrypted_key_out, encrypted_key_size);
}

dogecoin_bool dogecoin_bip38_decrypt_with_lot_sequence(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out,
    uint32_t* lot_out,
    uint32_t* sequence_out)
{
    if (lot_out) {
        *lot_out = 0;
    }
    if (sequence_out) {
        *sequence_out = 0;
    }
    return dogecoin_bip38_decrypt(encrypted_key, passphrase, private_key_out, compressed_out);
}
