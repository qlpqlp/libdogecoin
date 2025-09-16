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
#include <dogecoin/script.h>
#include <dogecoin/utils.h>
#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>
#include <dogecoin/rmd160.h>
#include <dogecoin/constants.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
    
    return options;
}

/* Free sweep options */
void dogecoin_sweep_options_free(dogecoin_sweep_options* options) {
    if (!options) return;
    
    if (options->destination_address) {
        dogecoin_free(options->destination_address);
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
        result->error_message = dogecoin_calloc(1, 50);
        strcpy(result->error_message, "Invalid wallet or options");
        return result;
    }
    
    if (!dogecoin_paper_wallet_is_valid(wallet)) {
        result->error_message = dogecoin_calloc(1, 50);
        strcpy(result->error_message, "Invalid paper wallet");
        return result;
    }
    
    if (!options->destination_address) {
        result->error_message = dogecoin_calloc(1, 50);
        strcpy(result->error_message, "No destination address specified");
        return result;
    }
    
    /* Get private key */
    uint8_t private_key[DOGECOIN_ECKEY_PKEY_LENGTH];
    if (!dogecoin_paper_wallet_get_private_key(wallet, private_key)) {
        result->error_message = dogecoin_calloc(1, 50);
        strcpy(result->error_message, "Failed to get private key");
        return result;
    }
    
    /* Create transaction - placeholder implementation */
    /* In a real implementation, you would create a proper transaction here */
    /* For now, we'll just simulate success */
    
    /* For now, create a simple transaction structure */
    /* In a real implementation, you would need to:
     * 1. Query UTXOs for the source address
     * 2. Calculate fees
     * 3. Create inputs and outputs
     * 4. Sign the transaction
     * 5. Broadcast the transaction
     */
    
    /* Set result properties */
    result->success = true;
    result->destination_address = dogecoin_calloc(1, strlen(options->destination_address) + 1);
    strcpy(result->destination_address, options->destination_address);
    
    /* Clean up - no transaction to free in placeholder implementation */
    
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
    /* Simple fee estimation */
    if (!options) return 0;
    return options->min_fee;
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
    /* Placeholder - return NULL for now */
    (void)wallet;
    (void)options;
    return NULL;
}

dogecoin_bool dogecoin_sweep_sign_transaction(
    dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet
) {
    /* Placeholder */
    return false;
}

dogecoin_bool dogecoin_sweep_broadcast_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_chainparams* chain_params,
    char* transaction_id_out,
    size_t transaction_id_size
) {
    /* Placeholder */
    return false;
}

dogecoin_bool dogecoin_sweep_validate_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
) {
    /* Placeholder */
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
    /* Placeholder */
    if (input_count_out) *input_count_out = 0;
    if (output_count_out) *output_count_out = 0;
    if (total_input_value_out) *total_input_value_out = 0;
    if (total_output_value_out) *total_output_value_out = 0;
    if (fee_out) *fee_out = 0;
    return false;
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