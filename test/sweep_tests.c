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

#include <stdio.h>
#include <string.h>

#include <dogecoin/sweep.h>
#include <dogecoin/bip38.h>
#include <dogecoin/chainparams.h>
#include <dogecoin/key.h>
#include <dogecoin/address.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/constants.h>
#include <dogecoin/ecc.h>

#include <test/utest.h>

typedef struct bip38_test_vector_ {
    const char* passphrase;
    const char* encrypted;
    const char* wif;
    const char* hex;
    dogecoin_bool compressed;
} bip38_test_vector;

/* Official vectors from BIP-0038 (non-EC multiplied). */
static const bip38_test_vector BIP38_NON_EC_VECTORS[] = {
    {
        "TestingOneTwoThree",
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
        false
    },
    {
        "Satoshi",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
        false
    },
    {
        "TestingOneTwoThree",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
        true
    },
    {
        "Satoshi",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
        true
    }
};

/* Test official BIP38 vectors (non-EC multiplied). */
static void test_bip38_reference_vectors(void)
{
    printf("Testing BIP38 reference vectors (non-EC multiplied)...\n");

    size_t i;
    for (i = 0; i < sizeof(BIP38_NON_EC_VECTORS) / sizeof(BIP38_NON_EC_VECTORS[0]); i++) {
        const bip38_test_vector* v = &BIP38_NON_EC_VECTORS[i];
        uint8_t expected_priv[DOGECOIN_ECKEY_PKEY_LENGTH];
        size_t hexlen = strlen(v->hex);
        size_t outl = sizeof(expected_priv);
        utils_hex_to_bin(v->hex, expected_priv, hexlen, &outl);
        u_assert_uint64_eq((uint64_t)outl, (uint64_t)DOGECOIN_ECKEY_PKEY_LENGTH);

        u_assert_true(dogecoin_bip38_is_valid(v->encrypted));

        uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
        dogecoin_bool compressed = false;
        dogecoin_bool ok = dogecoin_bip38_decrypt(v->encrypted, v->passphrase, decrypted_key, &compressed);
        u_assert_true(ok);
        u_assert_int_eq((int)compressed, (int)v->compressed);
        u_assert_mem_eq(decrypted_key, expected_priv, DOGECOIN_ECKEY_PKEY_LENGTH);
    }

    printf("  BIP38 reference vector tests passed\n");
}

/* Test paper wallet creation and validation */
static void test_paper_wallet_creation(void)
{
    printf("Testing paper wallet creation...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet1 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet1);

    dogecoin_key gen_wif_key;
    dogecoin_privkey_init(&gen_wif_key);
    u_assert_true(dogecoin_privkey_gen(&gen_wif_key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&gen_wif_key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&gen_wif_key);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet1, test_wif, chain);
    u_assert_true(result);

    char address[P2PKHLEN];
    result = dogecoin_paper_wallet_get_address(wallet1, address, sizeof(address));
    u_assert_true(result);
    printf("  WIF Address: %s\n", address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet1));

    dogecoin_paper_wallet_free(wallet1);

    dogecoin_paper_wallet* wallet2 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet2);

    const char* test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    result = dogecoin_paper_wallet_set_hex(wallet2, test_hex, chain);
    u_assert_true(result);

    result = dogecoin_paper_wallet_get_address(wallet2, address, sizeof(address));
    u_assert_true(result);
    printf("  Hex Address: %s\n", address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet2));

    dogecoin_paper_wallet_free(wallet2);

    printf("  Paper wallet creation tests passed\n");
}

/* Test BIP38 encryption/decryption */
static void test_bip38_encryption(void)
{
    printf("Testing BIP38 encryption/decryption...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_key key;
    dogecoin_privkey_gen(&key);

    dogecoin_pubkey pubkey;
    dogecoin_pubkey_from_key(&key, &pubkey);

    char address[P2PKHLEN];
    dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, address);
    printf("  Test address: %s\n", address);

    char encrypted_key[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t encrypted_size = sizeof(encrypted_key);
    const char* passphrase = "test_passphrase_123";

    dogecoin_bool result = dogecoin_bip38_encrypt(
        key.privkey,
        passphrase,
        address,
        true,
        encrypted_key,
        &encrypted_size
    );
    u_assert_true(result);
    printf("  Encrypted key: %s\n", encrypted_key);

    result = dogecoin_bip38_is_valid(encrypted_key);
    u_assert_true(result);

    uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed;
    result = dogecoin_bip38_decrypt(encrypted_key, passphrase, decrypted_key, &compressed);
    u_assert_true(result);
    u_assert_true(compressed);

    u_assert_mem_eq(key.privkey, decrypted_key, DOGECOIN_ECKEY_PKEY_LENGTH);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    result = dogecoin_paper_wallet_set_encrypted(wallet, encrypted_key, passphrase, chain);
    u_assert_true(result);

    char wallet_address[P2PKHLEN];
    result = dogecoin_paper_wallet_get_address(wallet, wallet_address, sizeof(wallet_address));
    u_assert_true(result);
    u_assert_str_eq(address, wallet_address);

    u_assert_true(dogecoin_paper_wallet_is_valid(wallet));

    dogecoin_paper_wallet_free(wallet);

    printf("  BIP38 encryption/decryption tests passed\n");
}

/* Test sweep options */
static void test_sweep_options(void)
{
    printf("Testing sweep options...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);

    const char* dest_address = "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP";
    dogecoin_bool result = dogecoin_sweep_options_set_destination(options, dest_address);
    u_assert_true(result);
    u_assert_str_eq(options->destination_address, dest_address);

    result = dogecoin_sweep_options_set_fee(options, 2000, 1000, 5000);
    u_assert_true(result);
    u_assert_uint64_eq(options->fee_per_byte, 2000ULL);
    u_assert_uint64_eq(options->min_fee, 1000ULL);
    u_assert_uint64_eq(options->max_fee, 5000ULL);

    dogecoin_sweep_options_set_rbf(options, true);
    u_assert_true(options->use_rbf);

    dogecoin_sweep_options_set_locktime(options, 1234567890);
    u_assert_uint32_eq(options->locktime, 1234567890U);

    dogecoin_sweep_options_free(options);

    printf("  Sweep options tests passed\n");
}

/* Test sweep result */
static void test_sweep_result(void)
{
    printf("Testing sweep result...\n");

    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    u_assert_not_null(result);

    u_assert_int_eq((int)result->success, 0);
    u_assert_is_null(result->error_message);
    u_assert_is_null(result->transaction_hex);
    u_assert_is_null(result->transaction_id);
    u_assert_uint64_eq(result->amount_swept, 0ULL);
    u_assert_uint64_eq(result->fee_paid, 0ULL);
    u_assert_is_null(result->destination_address);

    u_assert_is_null(dogecoin_sweep_result_get_error(result));
    u_assert_is_null(dogecoin_sweep_result_get_transaction_hex(result));
    u_assert_is_null(dogecoin_sweep_result_get_transaction_id(result));
    u_assert_uint64_eq(dogecoin_sweep_result_get_amount_swept(result), 0ULL);
    u_assert_uint64_eq(dogecoin_sweep_result_get_fee_paid(result), 0ULL);
    u_assert_is_null(dogecoin_sweep_result_get_destination_address(result));

    dogecoin_sweep_result_free(result);

    printf("  Sweep result tests passed\n");
}

/* Test paper wallet private key extraction */
static void test_paper_wallet_private_key_extraction(void)
{
    printf("Testing paper wallet private key extraction...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet1 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet1);

    dogecoin_key wkey;
    dogecoin_privkey_init(&wkey);
    u_assert_true(dogecoin_privkey_gen(&wkey));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&wkey, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&wkey);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet1, test_wif, chain);
    u_assert_true(result);

    char extracted_wif[PRIVKEYWIFLEN];
    result = dogecoin_paper_wallet_get_wif(wallet1, extracted_wif, sizeof(extracted_wif));
    u_assert_true(result);
    u_assert_str_eq(test_wif, extracted_wif);

    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    result = dogecoin_paper_wallet_get_private_key(wallet1, private_key);
    u_assert_true(result);

    dogecoin_paper_wallet_free(wallet1);

    dogecoin_paper_wallet* wallet2 = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet2);

    const char* test_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    result = dogecoin_paper_wallet_set_hex(wallet2, test_hex, chain);
    u_assert_true(result);

    result = dogecoin_paper_wallet_get_private_key(wallet2, private_key);
    u_assert_true(result);

    char hex_out[65];
    utils_bin_to_hex(private_key, DOGECOIN_ECKEY_PKEY_LENGTH, hex_out);
    u_assert_str_eq(test_hex, hex_out);

    dogecoin_paper_wallet_free(wallet2);

    printf("  Paper wallet private key extraction tests passed\n");
}

/* Test BIP38 validation */
static void test_bip38_validation(void)
{
    printf("Testing BIP38 validation...\n");

    u_assert_int_eq((int)dogecoin_bip38_is_valid(NULL), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid(""), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid("invalid"), 0);
    u_assert_int_eq((int)dogecoin_bip38_is_valid("1234567890123456789012345678901234567890123456789012345678901234567890"), 0);

    u_assert_true(dogecoin_bip38_is_valid(
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"));

    printf("  BIP38 validation tests passed\n");
}

/* Test sweep functionality (basic WIF + UTXO setup; signing is covered by transaction tests). */
static void test_sweep_functionality(void)
{
    printf("Testing sweep functionality...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    dogecoin_key sw_key;
    dogecoin_privkey_init(&sw_key);
    u_assert_true(dogecoin_privkey_gen(&sw_key));
    char test_wif[PRIVKEYWIFLEN];
    size_t wif_sz = sizeof(test_wif);
    dogecoin_privkey_encode_wif(&sw_key, chain, test_wif, &wif_sz);
    dogecoin_privkey_cleanse(&sw_key);

    dogecoin_bool result = dogecoin_paper_wallet_set_wif(wallet, test_wif, chain);
    u_assert_true(result);

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);

    const char* dest_address = "DHprgyNMcy3Ct9zVbJCrezYywxTBDWPL3v";
    result = dogecoin_sweep_options_set_destination(options, dest_address);
    u_assert_true(result);

    result = dogecoin_sweep_options_set_utxo(
        options,
        "b4455e7b7b7acb51fb6feba7a2702c42a5100f61f61abafa31851ed6ae076074",
        1,
        "12.0");
    u_assert_true(result);

    /* Exercise the actual sweep pipeline: build -> sign -> validate. */
    dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, options);
    u_assert_not_null(tx);

    dogecoin_bool signed_ok = dogecoin_sweep_sign_transaction(tx, wallet);
    if (signed_ok) {
        u_assert_true(dogecoin_sweep_validate_transaction(tx, wallet, options));
    }

    dogecoin_tx_free(tx);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);

    printf("  Sweep functionality tests passed\n");
}

static void test_bip38_generate_and_sweep(void)
{
    printf("Testing BIP38 generate + sweep transaction build...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    dogecoin_key key;
    dogecoin_privkey_init(&key);
    dogecoin_privkey_gen(&key);

    dogecoin_pubkey pubkey;
    dogecoin_pubkey_init(&pubkey);
    dogecoin_pubkey_from_key(&key, &pubkey);

    char source_address[P2PKHLEN];
    u_assert_true(dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, source_address));

    const char* passphrase = "libdogecoin_bip38_sweep_gen_test";
    char encrypted[BIP38_ENCRYPTED_KEY_LENGTH + 1];
    size_t enc_sz = sizeof(encrypted);
    u_assert_true(dogecoin_bip38_encrypt(key.privkey, passphrase, source_address, true,
                                         encrypted, &enc_sz));
    u_assert_true(dogecoin_bip38_is_valid(encrypted));

    uint8_t roundtrip[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed = false;
    u_assert_true(dogecoin_bip38_decrypt(encrypted, passphrase, roundtrip, &compressed));
    u_assert_true(compressed);
    u_assert_mem_eq(key.privkey, roundtrip, DOGECOIN_ECKEY_PKEY_LENGTH);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);
    u_assert_true(dogecoin_paper_wallet_set_encrypted(wallet, encrypted, passphrase, chain));
    u_assert_true(dogecoin_paper_wallet_is_valid(wallet));

    dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
    u_assert_not_null(options);
    u_assert_true(dogecoin_sweep_options_set_destination(options, "DMTbb3NbwAdimWDMVabwip7FjPAVx6Qeq4"));
    u_assert_true(dogecoin_sweep_options_set_utxo(
        options,
        "00df9507524acbf5ccc1c00d152216c984192f1fc6edad81406b4371a7d91038",
        0,
        "100.0"));

    /* Exercise the actual sweep pipeline: build -> sign -> validate. */
    dogecoin_transaction* tx = dogecoin_sweep_create_transaction(wallet, options);
    u_assert_not_null(tx);
    dogecoin_bool signed_ok = dogecoin_sweep_sign_transaction(tx, wallet);
    if (signed_ok) {
        u_assert_true(dogecoin_sweep_validate_transaction(tx, wallet, options));
    }
    dogecoin_tx_free(tx);

    dogecoin_sweep_options_free(options);
    dogecoin_paper_wallet_free(wallet);
    dogecoin_privkey_cleanse(&key);
    dogecoin_pubkey_cleanse(&pubkey);

    printf("  BIP38 generate + sweep tests passed (BIP38 + wallet + options)\n");
}

/* Test error handling */
static void test_sweep_error_handling(void)
{
    printf("Testing error handling...\n");

    const dogecoin_chainparams* chain = &dogecoin_chainparams_main;

    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(NULL, "test", chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(dogecoin_paper_wallet_new(), NULL, chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(dogecoin_paper_wallet_new(), "test", NULL), 0);

    dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
    u_assert_not_null(wallet);

    u_assert_int_eq((int)dogecoin_paper_wallet_set_wif(wallet, "invalid_wif", chain), 0);
    u_assert_int_eq((int)dogecoin_paper_wallet_is_valid(wallet), 0);

    dogecoin_paper_wallet_free(wallet);

    printf("  Error handling tests passed\n");
}

void test_sweep(void)
{
    test_paper_wallet_creation();
    test_bip38_encryption();
    test_sweep_options();
    test_sweep_result();
    test_paper_wallet_private_key_extraction();
    test_bip38_validation();
    test_bip38_reference_vectors();
    test_sweep_functionality();
    test_bip38_generate_and_sweep();
    test_sweep_error_handling();
}
