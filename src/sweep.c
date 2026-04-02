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

#include <dogecoin/sweep.h>
#include <dogecoin/bip38.h>
#include <dogecoin/key.h>
#include <dogecoin/address.h>
#include <dogecoin/transaction.h>
#include <dogecoin/koinu.h>
#include <dogecoin/tx.h>
#include <dogecoin/cstr.h>
#include <dogecoin/script.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/constants.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void sweep_result_fail(dogecoin_sweep_result* r, const char* msg)
{
    if (!r || !msg) return;
    if (r->error_message) dogecoin_free(r->error_message);
    r->error_message = dogecoin_calloc(1, strlen(msg) + 1);
    if (r->error_message) strcpy(r->error_message, msg);
    r->success = false;
}

static dogecoin_bool sweep_options_utxo_ok(const dogecoin_sweep_options* o)
{
    return o && o->utxo_txid && o->utxo_txid[0] && o->utxo_vout >= 0 && o->utxo_total_doge && o->utxo_total_doge[0];
}

/* Fee and output amount (koinu); fills fee_doge / out_doge buffers for finalize_transaction / add_output. */
static dogecoin_bool sweep_compute_amounts(
    const dogecoin_sweep_options* options,
    uint64_t* fee_koinu_out,
    uint64_t* out_koinu_out,
    char* fee_doge,
    char* out_doge)
{
    char total_mut[64];
    strncpy(total_mut, options->utxo_total_doge, sizeof(total_mut) - 1);
    total_mut[sizeof(total_mut) - 1] = '\0';
    uint64_t total_koinu = coins_to_koinu_str(total_mut);
    /* Rough vsize: version + vin/vout counts + 1 signed P2PKH in + 1 P2PKH out + locktime */
    size_t est_vsize = 10u + 180u + 34u;
    uint64_t fee_koinu = options->fee_per_byte * est_vsize;
    if (fee_koinu < options->min_fee) fee_koinu = options->min_fee;
    if (fee_koinu > options->max_fee) fee_koinu = options->max_fee;
    if (total_koinu <= fee_koinu) return false;
    uint64_t out_koinu = total_koinu - fee_koinu;
    if (!koinu_to_coins_str(fee_koinu, fee_doge)) return false;
    if (!koinu_to_coins_str(out_koinu, out_doge)) return false;
    *fee_koinu_out = fee_koinu;
    *out_koinu_out = out_koinu;
    return true;
}

/* Build unsigned tx in the working-transaction table. On success, *txindex_out is valid until clear_transaction. */
static dogecoin_bool sweep_build_unsigned_tx(
    const dogecoin_sweep_options* options,
    const char* fee_doge,
    const char* out_doge,
    int* txindex_out)
{
    char dest_copy[P2PKHLEN];
    char total_copy[64];
    strncpy(dest_copy, options->destination_address, sizeof(dest_copy) - 1);
    dest_copy[sizeof(dest_copy) - 1] = '\0';
    strncpy(total_copy, options->utxo_total_doge, sizeof(total_copy) - 1);
    total_copy[sizeof(total_copy) - 1] = '\0';

    int txindex = start_transaction();
    if (!add_utxo(txindex, options->utxo_txid, options->utxo_vout)) {
        clear_transaction(txindex);
        return false;
    }
    if (!add_output(txindex, dest_copy, (char*)out_doge)) {
        clear_transaction(txindex);
        return false;
    }
    char* raw = finalize_transaction(txindex, dest_copy, (char*)fee_doge, total_copy, NULL);
    if (!raw) {
        clear_transaction(txindex);
        return false;
    }
    *txindex_out = txindex;
    return true;
}

/* Initialize a paper wallet structure */
dogecoin_paper_wallet* dogecoin_paper_wallet_new(void) {
    dogecoin_paper_wallet* wallet = dogecoin_calloc(1, sizeof(dogecoin_paper_wallet));
    if (!wallet) return NULL;
    
    wallet->private_key_wif = NULL;
    wallet->private_key_hex = NULL;
    wallet->encrypted_private_key = NULL;
    wallet->passphrase = NULL;
    wallet->address = NULL;
    wallet->compressed = false;
    wallet->is_encrypted = false;
    wallet->chain_params = NULL;
    
    return wallet;
}

/* Free a paper wallet structure */
void dogecoin_paper_wallet_free(dogecoin_paper_wallet* wallet) {
    if (!wallet) return;
    
    if (wallet->private_key_wif) {
        dogecoin_free(wallet->private_key_wif);
    }
    if (wallet->private_key_hex) {
        dogecoin_free(wallet->private_key_hex);
    }
    if (wallet->encrypted_private_key) {
        dogecoin_free(wallet->encrypted_private_key);
    }
    if (wallet->passphrase) {
        dogecoin_free(wallet->passphrase);
    }
    if (wallet->address) {
        dogecoin_free(wallet->address);
    }
    
    dogecoin_free(wallet);
}

/* Initialize a sweep result structure */
dogecoin_sweep_result* dogecoin_sweep_result_new(void) {
    dogecoin_sweep_result* result = dogecoin_calloc(1, sizeof(dogecoin_sweep_result));
    if (!result) return NULL;
    
    result->success = false;
    result->error_message = NULL;
    result->transaction_hex = NULL;
    result->transaction_id = NULL;
    result->amount_swept = 0;
    result->fee_paid = 0;
    result->destination_address = NULL;
    
    return result;
}

/* Free a sweep result structure */
void dogecoin_sweep_result_free(dogecoin_sweep_result* result) {
    if (!result) return;
    
    if (result->error_message) {
        dogecoin_free(result->error_message);
    }
    if (result->transaction_hex) {
        dogecoin_free(result->transaction_hex);
    }
    if (result->transaction_id) {
        dogecoin_free(result->transaction_id);
    }
    if (result->destination_address) {
        dogecoin_free(result->destination_address);
    }
    
    dogecoin_free(result);
}

/* Initialize sweep options with defaults */
dogecoin_sweep_options* dogecoin_sweep_options_new(const dogecoin_chainparams* chain_params) {
    dogecoin_sweep_options* options = dogecoin_calloc(1, sizeof(dogecoin_sweep_options));
    if (!options) return NULL;
    
    options->destination_address = NULL;
    options->fee_per_byte = DOGECOIN_SWEEP_DEFAULT_FEE_PER_BYTE;
    options->min_fee = DOGECOIN_SWEEP_DEFAULT_MIN_FEE;
    options->max_fee = DOGECOIN_SWEEP_DEFAULT_MAX_FEE;
    options->use_rbf = false;
    options->locktime = 0;
    options->chain_params = chain_params;
    options->utxo_txid = NULL;
    options->utxo_vout = -1;
    options->utxo_total_doge = NULL;
    
    return options;
}

/* Free sweep options */
void dogecoin_sweep_options_free(dogecoin_sweep_options* options) {
    if (!options) return;
    
    if (options->destination_address) {
        dogecoin_free(options->destination_address);
    }
    if (options->utxo_txid) {
        dogecoin_free(options->utxo_txid);
    }
    if (options->utxo_total_doge) {
        dogecoin_free(options->utxo_total_doge);
    }
    
    dogecoin_free(options);
}

/* Set paper wallet from WIF private key */
dogecoin_bool dogecoin_paper_wallet_set_wif(
    dogecoin_paper_wallet* wallet,
    const char* wif_private_key,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !wif_private_key || !chain_params) return false;
    
    /* Decode WIF to get private key */
    dogecoin_key key;
    if (!dogecoin_privkey_decode_wif(wif_private_key, chain_params, &key)) {
        return false;
    }
    
    /* Get address from private key */
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_from_key(&key, &pubkey);
    
    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        return false;
    }
    
    /* Set wallet properties */
    wallet->private_key_wif = dogecoin_calloc(1, strlen(wif_private_key) + 1);
    if (!wallet->private_key_wif) return false;
    strcpy(wallet->private_key_wif, wif_private_key);
    
    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        dogecoin_free(wallet->private_key_wif);
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = true; /* Assume compressed for now */
    wallet->is_encrypted = false;
    wallet->chain_params = chain_params;
    
    return true;
}

/* Set paper wallet from hex private key */
dogecoin_bool dogecoin_paper_wallet_set_hex(
    dogecoin_paper_wallet* wallet,
    const char* hex_private_key,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !hex_private_key || !chain_params) return false;
    
    /* Convert hex to bytes */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    size_t private_key_len;
    utils_hex_to_bin(hex_private_key, private_key, strlen(hex_private_key), &private_key_len);
    if (private_key_len != DOGECOIN_ECKEY_PKEY_LENGTH) {
        return false;
    }
    
    /* Create key from private key */
    dogecoin_key key;
    memcpy(key.privkey, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    
    /* Get address from private key */
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_from_key(&key, &pubkey);
    
    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        return false;
    }
    
    /* Set wallet properties */
    wallet->private_key_hex = dogecoin_calloc(1, strlen(hex_private_key) + 1);
    if (!wallet->private_key_hex) return false;
    strcpy(wallet->private_key_hex, hex_private_key);
    
    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        dogecoin_free(wallet->private_key_hex);
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = true; /* Assume compressed for now */
    wallet->is_encrypted = false;
    wallet->chain_params = chain_params;
    
    return true;
}

/* Set paper wallet from BIP38 encrypted private key */
dogecoin_bool dogecoin_paper_wallet_set_encrypted(
    dogecoin_paper_wallet* wallet,
    const char* encrypted_private_key,
    const char* passphrase,
    const dogecoin_chainparams* chain_params
) {
    if (!wallet || !encrypted_private_key || !passphrase || !chain_params) return false;
    
    /* Decrypt private key */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    dogecoin_bool compressed;
    if (!dogecoin_bip38_decrypt(encrypted_private_key, passphrase, private_key, &compressed)) {
        return false;
    }
    
    /* Create key from private key */
    dogecoin_key key;
    memcpy(key.privkey, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    
    /* Get address from private key */
    dogecoin_pubkey pubkey;
    dogecoin_pubkey_from_key(&key, &pubkey);
    
    char address[P2PKHLEN];
    if (!dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain_params, address)) {
        return false;
    }
    
    /* Set wallet properties */
    wallet->encrypted_private_key = dogecoin_calloc(1, strlen(encrypted_private_key) + 1);
    if (!wallet->encrypted_private_key) return false;
    strcpy(wallet->encrypted_private_key, encrypted_private_key);
    
    wallet->passphrase = dogecoin_calloc(1, strlen(passphrase) + 1);
    if (!wallet->passphrase) {
        dogecoin_free(wallet->encrypted_private_key);
        return false;
    }
    strcpy(wallet->passphrase, passphrase);
    
    wallet->address = dogecoin_calloc(1, strlen(address) + 1);
    if (!wallet->address) {
        dogecoin_free(wallet->encrypted_private_key);
        dogecoin_free(wallet->passphrase);
        return false;
    }
    strcpy(wallet->address, address);
    
    wallet->compressed = compressed;
    wallet->is_encrypted = true;
    wallet->chain_params = chain_params;
    
    return true;
}

/* Get the address from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_address(
    const dogecoin_paper_wallet* wallet,
    char* address_out,
    size_t address_size
) {
    if (!wallet || !address_out || !wallet->address) return false;
    
    if (strlen(wallet->address) >= address_size) return false;
    
    strcpy(address_out, wallet->address);
    return true;
}

/* Get the private key from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_private_key(
    const dogecoin_paper_wallet* wallet,
    uint8_t* private_key_out
) {
    if (!wallet || !private_key_out) return false;
    
    if (wallet->private_key_hex) {
        /* Convert hex to bytes */
        size_t private_key_len;
        utils_hex_to_bin(wallet->private_key_hex, private_key_out, strlen(wallet->private_key_hex), &private_key_len);
        return (private_key_len == DOGECOIN_ECKEY_PKEY_LENGTH);
    } else if (wallet->encrypted_private_key && wallet->passphrase) {
        /* Decrypt private key */
        dogecoin_bool compressed;
        return dogecoin_bip38_decrypt(wallet->encrypted_private_key, wallet->passphrase, private_key_out, &compressed);
    } else if (wallet->private_key_wif) {
        /* Decode WIF to get private key */
        dogecoin_key key;
        if (!dogecoin_privkey_decode_wif(wallet->private_key_wif, wallet->chain_params, &key)) {
            return false;
        }
        memcpy(private_key_out, key.privkey, DOGECOIN_ECKEY_PKEY_LENGTH);
        return true;
    }
    
    return false;
}

/* Get the WIF private key from a paper wallet */
dogecoin_bool dogecoin_paper_wallet_get_wif(
    const dogecoin_paper_wallet* wallet,
    char* wif_out,
    size_t wif_size
) {
    if (!wallet || !wif_out) return false;
    
    if (wallet->private_key_wif) {
        if (strlen(wallet->private_key_wif) >= wif_size) return false;
        strcpy(wif_out, wallet->private_key_wif);
        return true;
    }
    
    /* Convert from other formats */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    if (!dogecoin_paper_wallet_get_private_key(wallet, private_key)) {
        return false;
    }
    
    dogecoin_key key;
    memcpy(key.privkey, private_key, DOGECOIN_ECKEY_PKEY_LENGTH);
    
    size_t wif_len = wif_size;
    dogecoin_privkey_encode_wif(&key, wallet->chain_params, wif_out, &wif_len);
    return true;
}

/* Check if a paper wallet is valid */
dogecoin_bool dogecoin_paper_wallet_is_valid(const dogecoin_paper_wallet* wallet) {
    if (!wallet) return false;
    
    /* Check if we have at least one private key format */
    if (!wallet->private_key_wif && !wallet->private_key_hex && !wallet->encrypted_private_key) {
        return false;
    }
    
    /* Check if we have an address */
    if (!wallet->address) return false;
    
    /* Try to get private key to verify it's valid */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    if (!dogecoin_paper_wallet_get_private_key(wallet, private_key)) {
        return false;
    }
    
    return true;
}

/* Sweep a paper wallet to a destination address */
dogecoin_sweep_result* dogecoin_sweep_paper_wallet(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    if (!result) return NULL;
    
    /* Validate inputs */
    if (!wallet || !options) {
        sweep_result_fail(result, "Invalid wallet or options");
        return result;
    }
    
    if (!dogecoin_paper_wallet_is_valid(wallet)) {
        sweep_result_fail(result, "Invalid paper wallet");
        return result;
    }
    
    if (!options->destination_address) {
        sweep_result_fail(result, "No destination address specified");
        return result;
    }

    if (!sweep_options_utxo_ok(options)) {
        sweep_result_fail(result,
            "No UTXO specified: set prevout with dogecoin_sweep_options_set_utxo (txid, vout, total input amount)");
        return result;
    }
    
    char fee_doge[64];
    char out_doge[64];
    uint64_t fee_koinu = 0;
    uint64_t out_koinu = 0;
    if (!sweep_compute_amounts(options, &fee_koinu, &out_koinu, fee_doge, out_doge)) {
        sweep_result_fail(result, "Fee exceeds UTXO value or amount conversion failed");
        return result;
    }

    int txindex = 0;
    if (!sweep_build_unsigned_tx(options, fee_doge, out_doge, &txindex)) {
        sweep_result_fail(result, "Building unsigned sweep transaction failed");
        return result;
    }

    char wif[PRIVKEYWIFLEN];
    size_t wiflen = sizeof(wif);
    if (!dogecoin_paper_wallet_get_wif(wallet, wif, wiflen)) {
        clear_transaction(txindex);
        sweep_result_fail(result, "Failed to encode private key as WIF for signing");
        return result;
    }

    char* script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(wif);
    if (!script_pubkey) {
        clear_transaction(txindex);
        sweep_result_fail(result, "Failed to derive pubkey script from WIF");
        return result;
    }

    if (!sign_transaction(txindex, script_pubkey, wif)) {
        dogecoin_free(script_pubkey);
        clear_transaction(txindex);
        sweep_result_fail(result, "sign_transaction failed");
        return result;
    }
    dogecoin_free(script_pubkey);

    char hexbuf[TXHEXMAXLEN];
    int hexlen = get_raw_transaction_ex(txindex, hexbuf, sizeof(hexbuf));
    if (hexlen <= 0) {
        clear_transaction(txindex);
        sweep_result_fail(result, "get_raw_transaction_ex failed after sign");
        return result;
    }

    dogecoin_tx* stx = dogecoin_tx_new();
    if (!stx) {
        clear_transaction(txindex);
        sweep_result_fail(result, "out of memory");
        return result;
    }
    uint8_t* bindata = dogecoin_malloc((size_t)hexlen / 2 + 1);
    if (!bindata) {
        dogecoin_tx_free(stx);
        clear_transaction(txindex);
        sweep_result_fail(result, "out of memory");
        return result;
    }
    size_t binlen = 0;
    utils_hex_to_bin(hexbuf, bindata, (size_t)hexlen, &binlen);
    if (!dogecoin_tx_deserialize(bindata, binlen, stx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(stx);
        clear_transaction(txindex);
        sweep_result_fail(result, "deserialize signed transaction failed");
        return result;
    }
    dogecoin_free(bindata);

    uint256_t txhash;
    dogecoin_tx_hash(stx, txhash);
    dogecoin_tx_free(stx);
    clear_transaction(txindex);

    char txidhex[65];
    utils_bin_to_hex((unsigned char*)txhash, sizeof(txhash), txidhex);
    utils_reverse_hex(txidhex, 64);
    txidhex[64] = '\0';

    result->transaction_hex = dogecoin_calloc(1, (size_t)hexlen + 1);
    result->transaction_id = dogecoin_calloc(1, strlen(txidhex) + 1);
    if (!result->transaction_hex || !result->transaction_id) {
        if (result->transaction_hex) dogecoin_free(result->transaction_hex);
        if (result->transaction_id) dogecoin_free(result->transaction_id);
        result->transaction_hex = NULL;
        result->transaction_id = NULL;
        sweep_result_fail(result, "out of memory");
        return result;
    }
    memcpy(result->transaction_hex, hexbuf, (size_t)hexlen + 1);
    strcpy(result->transaction_id, txidhex);

    result->amount_swept = out_koinu;
    result->fee_paid = fee_koinu;
    result->destination_address = dogecoin_calloc(1, strlen(options->destination_address) + 1);
    if (!result->destination_address) {
        dogecoin_free(result->transaction_hex);
        dogecoin_free(result->transaction_id);
        result->transaction_hex = NULL;
        result->transaction_id = NULL;
        sweep_result_fail(result, "out of memory");
        return result;
    }
    strcpy(result->destination_address, options->destination_address);
    result->success = true;
    return result;
}

/* Placeholder implementations for remaining functions */
dogecoin_sweep_result* dogecoin_sweep_multiple_paper_wallets(
    const dogecoin_paper_wallet* wallets,
    size_t wallet_count,
    const dogecoin_sweep_options* options
) {
    /* For now, just return an error */
    dogecoin_sweep_result* result = dogecoin_sweep_result_new();
    if (result) {
        result->error_message = dogecoin_calloc(1, 50);
        strcpy(result->error_message, "Multiple wallet sweep not implemented");
    }
    return result;
}

uint64_t dogecoin_sweep_estimate_fee(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    (void)wallet;
    if (!options) return 0;
    size_t est_vsize = 10u + 180u + 34u;
    uint64_t fee_koinu = options->fee_per_byte * est_vsize;
    if (fee_koinu < options->min_fee) fee_koinu = options->min_fee;
    if (fee_koinu > options->max_fee) fee_koinu = options->max_fee;
    return fee_koinu;
}

dogecoin_bool dogecoin_sweep_get_balance(
    const char* address,
    const dogecoin_chainparams* chain_params,
    uint64_t* balance_out
) {
    /* Placeholder - would need to query blockchain */
    if (balance_out) *balance_out = 0;
    return false;
}

dogecoin_transaction* dogecoin_sweep_create_transaction(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    (void)wallet;
    if (!options || !options->destination_address || !sweep_options_utxo_ok(options)) return NULL;

    char fee_doge[64];
    char out_doge[64];
    uint64_t fee_koinu = 0;
    uint64_t out_koinu = 0;
    if (!sweep_compute_amounts(options, &fee_koinu, &out_koinu, fee_doge, out_doge)) return NULL;

    int txindex = 0;
    if (!sweep_build_unsigned_tx(options, fee_doge, out_doge, &txindex)) return NULL;

    char hexbuf[TXHEXMAXLEN];
    int hexlen = get_raw_transaction_ex(txindex, hexbuf, sizeof(hexbuf));
    if (hexlen <= 0) {
        clear_transaction(txindex);
        return NULL;
    }

    dogecoin_tx* tx = dogecoin_tx_new();
    if (!tx) {
        clear_transaction(txindex);
        return NULL;
    }
    uint8_t* bindata = dogecoin_malloc((size_t)hexlen / 2 + 1);
    if (!bindata) {
        dogecoin_tx_free(tx);
        clear_transaction(txindex);
        return NULL;
    }
    size_t binlen = 0;
    utils_hex_to_bin(hexbuf, bindata, (size_t)hexlen, &binlen);
    if (!dogecoin_tx_deserialize(bindata, binlen, tx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(tx);
        clear_transaction(txindex);
        return NULL;
    }
    dogecoin_free(bindata);
    clear_transaction(txindex);
    return tx;
}

dogecoin_bool dogecoin_sweep_sign_transaction(
    dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet
) {
    if (!transaction || !wallet || !dogecoin_paper_wallet_is_valid(wallet)) return false;

    char wif[PRIVKEYWIFLEN];
    size_t wiflen = sizeof(wif);
    if (!dogecoin_paper_wallet_get_wif(wallet, wif, wiflen)) return false;

    cstring* ser = cstr_new_sz(1024);
    if (!ser) return false;
    dogecoin_tx_serialize(ser, transaction);
    char* hex = dogecoin_malloc(ser->len * 2 + 1);
    if (!hex) {
        cstr_free(ser, true);
        return false;
    }
    utils_bin_to_hex((unsigned char*)ser->str, ser->len, hex);
    cstr_free(ser, true);

    int txidx = store_raw_transaction(hex);
    dogecoin_free(hex);
    if (txidx <= 0) return false;

    char* script_pubkey = dogecoin_private_key_wif_to_pubkey_hash(wif);
    if (!script_pubkey) {
        clear_transaction(txidx);
        return false;
    }
    if (!sign_transaction(txidx, script_pubkey, wif)) {
        dogecoin_free(script_pubkey);
        clear_transaction(txidx);
        return false;
    }
    dogecoin_free(script_pubkey);

    char signedbuf[TXHEXMAXLEN];
    if (!get_raw_transaction_ex(txidx, signedbuf, sizeof(signedbuf))) {
        clear_transaction(txidx);
        return false;
    }
    uint8_t* bindata = dogecoin_malloc(strlen(signedbuf) / 2 + 1);
    if (!bindata) {
        clear_transaction(txidx);
        return false;
    }
    size_t binlen = 0;
    utils_hex_to_bin(signedbuf, bindata, strlen(signedbuf), &binlen);
    dogecoin_tx* signed_tx = dogecoin_tx_new();
    if (!signed_tx) {
        dogecoin_free(bindata);
        clear_transaction(txidx);
        return false;
    }
    if (!dogecoin_tx_deserialize(bindata, binlen, signed_tx, NULL)) {
        dogecoin_free(bindata);
        dogecoin_tx_free(signed_tx);
        clear_transaction(txidx);
        return false;
    }
    dogecoin_free(bindata);
    dogecoin_tx_copy(transaction, signed_tx);
    dogecoin_tx_free(signed_tx);
    clear_transaction(txidx);
    return true;
}

dogecoin_bool dogecoin_sweep_broadcast_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_chainparams* chain_params,
    char* transaction_id_out,
    size_t transaction_id_size
) {
    (void)transaction;
    (void)chain_params;
    (void)transaction_id_out;
    (void)transaction_id_size;
    /* Broadcasting requires a connected node / RPC; not implemented in this module. */
    return false;
}

dogecoin_bool dogecoin_sweep_validate_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    if (!transaction || !wallet || !options || !options->destination_address) return false;
    size_t i;
    for (i = 0; i < transaction->vout->len; i++) {
        dogecoin_tx_out* o = vector_idx(transaction->vout, i);
        char addr[P2PKHLEN];
        dogecoin_mem_zero(addr, sizeof(addr));
        int is_mainnet = (options->destination_address[0] == 'D');
        if (dogecoin_tx_out_pubkey_hash_to_p2pkh_address(o, addr, is_mainnet) &&
            strcmp(addr, options->destination_address) == 0)
            return true;
    }
    return false;
}

dogecoin_bool dogecoin_sweep_get_stats(
    const dogecoin_transaction* transaction,
    uint64_t* input_count_out,
    uint64_t* output_count_out,
    uint64_t* total_input_value_out,
    uint64_t* total_output_value_out,
    uint64_t* fee_out
) {
    if (!transaction) return false;
    if (input_count_out) *input_count_out = transaction->vin->len;
    if (output_count_out) *output_count_out = transaction->vout->len;
    if (total_input_value_out) *total_input_value_out = 0; /* not available from raw tx alone */
    uint64_t outsum = 0;
    size_t i;
    for (i = 0; i < transaction->vout->len; i++) {
        dogecoin_tx_out* o = vector_idx(transaction->vout, i);
        outsum += (uint64_t)o->value;
    }
    if (total_output_value_out) *total_output_value_out = outsum;
    if (fee_out) *fee_out = 0; /* needs input values from UTXO set */
    return true;
}

/* Setter functions */
dogecoin_bool dogecoin_sweep_options_set_destination(
    dogecoin_sweep_options* options,
    const char* destination_address
) {
    if (!options || !destination_address) return false;
    
    if (options->destination_address) {
        dogecoin_free(options->destination_address);
    }
    
    options->destination_address = dogecoin_calloc(1, strlen(destination_address) + 1);
    if (!options->destination_address) return false;
    
    strcpy(options->destination_address, destination_address);
    return true;
}

dogecoin_bool dogecoin_sweep_options_set_fee(
    dogecoin_sweep_options* options,
    uint64_t fee_per_byte,
    uint64_t min_fee,
    uint64_t max_fee
) {
    if (!options) return false;
    
    options->fee_per_byte = fee_per_byte;
    options->min_fee = min_fee;
    options->max_fee = max_fee;
    
    return true;
}

void dogecoin_sweep_options_set_rbf(
    dogecoin_sweep_options* options,
    dogecoin_bool use_rbf
) {
    if (options) {
        options->use_rbf = use_rbf;
    }
}

void dogecoin_sweep_options_set_locktime(
    dogecoin_sweep_options* options,
    uint32_t locktime
) {
    if (options) {
        options->locktime = locktime;
    }
}

dogecoin_bool dogecoin_sweep_options_set_utxo(
    dogecoin_sweep_options* options,
    const char* txid_hex,
    int vout,
    const char* total_input_doge)
{
    if (!options || !txid_hex || !total_input_doge || vout < 0) return false;

    if (options->utxo_txid) {
        dogecoin_free(options->utxo_txid);
        options->utxo_txid = NULL;
    }
    if (options->utxo_total_doge) {
        dogecoin_free(options->utxo_total_doge);
        options->utxo_total_doge = NULL;
    }

    options->utxo_txid = dogecoin_calloc(1, strlen(txid_hex) + 1);
    options->utxo_total_doge = dogecoin_calloc(1, strlen(total_input_doge) + 1);
    if (!options->utxo_txid || !options->utxo_total_doge) {
        if (options->utxo_txid) dogecoin_free(options->utxo_txid);
        if (options->utxo_total_doge) dogecoin_free(options->utxo_total_doge);
        options->utxo_txid = NULL;
        options->utxo_total_doge = NULL;
        return false;
    }
    strcpy(options->utxo_txid, txid_hex);
    strcpy(options->utxo_total_doge, total_input_doge);
    options->utxo_vout = vout;
    return true;
}

/* Getter functions */
const char* dogecoin_sweep_result_get_error(const dogecoin_sweep_result* result) {
    return result ? result->error_message : NULL;
}

const char* dogecoin_sweep_result_get_transaction_hex(const dogecoin_sweep_result* result) {
    return result ? result->transaction_hex : NULL;
}

const char* dogecoin_sweep_result_get_transaction_id(const dogecoin_sweep_result* result) {
    return result ? result->transaction_id : NULL;
}

uint64_t dogecoin_sweep_result_get_amount_swept(const dogecoin_sweep_result* result) {
    return result ? result->amount_swept : 0;
}

uint64_t dogecoin_sweep_result_get_fee_paid(const dogecoin_sweep_result* result) {
    return result ? result->fee_paid : 0;
}

const char* dogecoin_sweep_result_get_destination_address(const dogecoin_sweep_result* result) {
    return result ? result->destination_address : NULL;
}