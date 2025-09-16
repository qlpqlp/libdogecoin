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

#ifndef __LIBDOGECOIN_SWEEP_H__
#define __LIBDOGECOIN_SWEEP_H__

#include <stdint.h>
#include <stddef.h>
#include <dogecoin/dogecoin.h>
#include <dogecoin/chainparams.h>

/* Forward declaration */
typedef struct dogecoin_transaction_ dogecoin_transaction;

LIBDOGECOIN_BEGIN_DECL

/* Sweep result structure */
typedef struct {
    dogecoin_bool success;
    char* error_message;
    char* transaction_hex;
    char* transaction_id;
    uint64_t amount_swept;
    uint64_t fee_paid;
    char* destination_address;
} dogecoin_sweep_result;

/* Paper wallet structure */
typedef struct {
    char* private_key_wif;
    char* private_key_hex;
    char* encrypted_private_key; /* BIP38 encrypted */
    char* passphrase; /* For BIP38 decryption */
    char* address;
    dogecoin_bool compressed;
    dogecoin_bool is_encrypted;
    const dogecoin_chainparams* chain_params;
} dogecoin_paper_wallet;

/* Sweep options structure */
typedef struct {
    char* destination_address;
    uint64_t fee_per_byte; /* Fee in satoshis per byte */
    uint64_t min_fee; /* Minimum fee in satoshis */
    uint64_t max_fee; /* Maximum fee in satoshis */
    dogecoin_bool use_rbf; /* Replace-by-fee */
    uint32_t locktime; /* Locktime for transaction */
    const dogecoin_chainparams* chain_params;
} dogecoin_sweep_options;

/* Default sweep options */
#define DOGECOIN_SWEEP_DEFAULT_FEE_PER_BYTE 1000 /* 0.01 DOGE per KB */
#define DOGECOIN_SWEEP_DEFAULT_MIN_FEE 1000 /* 0.01 DOGE */
#define DOGECOIN_SWEEP_DEFAULT_MAX_FEE 1000000 /* 10 DOGE */

/*
 * Function declarations
 */

/* Initialize a paper wallet structure */
LIBDOGECOIN_API dogecoin_paper_wallet* dogecoin_paper_wallet_new(void);

/* Free a paper wallet structure */
LIBDOGECOIN_API void dogecoin_paper_wallet_free(dogecoin_paper_wallet* wallet);

/* Initialize a sweep result structure */
LIBDOGECOIN_API dogecoin_sweep_result* dogecoin_sweep_result_new(void);

/* Free a sweep result structure */
LIBDOGECOIN_API void dogecoin_sweep_result_free(dogecoin_sweep_result* result);

/* Initialize sweep options with defaults */
LIBDOGECOIN_API dogecoin_sweep_options* dogecoin_sweep_options_new(const dogecoin_chainparams* chain_params);

/* Free sweep options */
LIBDOGECOIN_API void dogecoin_sweep_options_free(dogecoin_sweep_options* options);

/* Set paper wallet from WIF private key */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_set_wif(
    dogecoin_paper_wallet* wallet,
    const char* wif_private_key,
    const dogecoin_chainparams* chain_params
);

/* Set paper wallet from hex private key */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_set_hex(
    dogecoin_paper_wallet* wallet,
    const char* hex_private_key,
    const dogecoin_chainparams* chain_params
);

/* Set paper wallet from BIP38 encrypted private key */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_set_encrypted(
    dogecoin_paper_wallet* wallet,
    const char* encrypted_private_key,
    const char* passphrase,
    const dogecoin_chainparams* chain_params
);

/* Get the address from a paper wallet */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_get_address(
    const dogecoin_paper_wallet* wallet,
    char* address_out,
    size_t address_size
);

/* Get the private key from a paper wallet */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_get_private_key(
    const dogecoin_paper_wallet* wallet,
    uint8_t* private_key_out
);

/* Get the WIF private key from a paper wallet */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_get_wif(
    const dogecoin_paper_wallet* wallet,
    char* wif_out,
    size_t wif_size
);

/* Check if a paper wallet is valid */
LIBDOGECOIN_API dogecoin_bool dogecoin_paper_wallet_is_valid(const dogecoin_paper_wallet* wallet);

/* Sweep a paper wallet to a destination address */
LIBDOGECOIN_API dogecoin_sweep_result* dogecoin_sweep_paper_wallet(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
);

/* Sweep multiple paper wallets to a destination address */
LIBDOGECOIN_API dogecoin_sweep_result* dogecoin_sweep_multiple_paper_wallets(
    const dogecoin_paper_wallet* wallets,
    size_t wallet_count,
    const dogecoin_sweep_options* options
);

/* Estimate the fee for sweeping a paper wallet */
LIBDOGECOIN_API uint64_t dogecoin_sweep_estimate_fee(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
);

/* Get the balance of a paper wallet address */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_get_balance(
    const char* address,
    const dogecoin_chainparams* chain_params,
    uint64_t* balance_out
);

/* Create a sweep transaction without broadcasting */
LIBDOGECOIN_API dogecoin_transaction* dogecoin_sweep_create_transaction(
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
);

/* Sign a sweep transaction */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_sign_transaction(
    dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet
);

/* Broadcast a sweep transaction */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_broadcast_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_chainparams* chain_params,
    char* transaction_id_out,
    size_t transaction_id_size
);

/* Validate a sweep transaction */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_validate_transaction(
    const dogecoin_transaction* transaction,
    const dogecoin_paper_wallet* wallet,
    const dogecoin_sweep_options* options
);

/* Get sweep transaction statistics */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_get_stats(
    const dogecoin_transaction* transaction,
    uint64_t* input_count_out,
    uint64_t* output_count_out,
    uint64_t* total_input_value_out,
    uint64_t* total_output_value_out,
    uint64_t* fee_out
);

/* Set sweep options destination address */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_options_set_destination(
    dogecoin_sweep_options* options,
    const char* destination_address
);

/* Set sweep options fee */
LIBDOGECOIN_API dogecoin_bool dogecoin_sweep_options_set_fee(
    dogecoin_sweep_options* options,
    uint64_t fee_per_byte,
    uint64_t min_fee,
    uint64_t max_fee
);

/* Set sweep options RBF */
LIBDOGECOIN_API void dogecoin_sweep_options_set_rbf(
    dogecoin_sweep_options* options,
    dogecoin_bool use_rbf
);

/* Set sweep options locktime */
LIBDOGECOIN_API void dogecoin_sweep_options_set_locktime(
    dogecoin_sweep_options* options,
    uint32_t locktime
);

/* Get sweep result error message */
LIBDOGECOIN_API const char* dogecoin_sweep_result_get_error(const dogecoin_sweep_result* result);

/* Get sweep result transaction hex */
LIBDOGECOIN_API const char* dogecoin_sweep_result_get_transaction_hex(const dogecoin_sweep_result* result);

/* Get sweep result transaction ID */
LIBDOGECOIN_API const char* dogecoin_sweep_result_get_transaction_id(const dogecoin_sweep_result* result);

/* Get sweep result amount swept */
LIBDOGECOIN_API uint64_t dogecoin_sweep_result_get_amount_swept(const dogecoin_sweep_result* result);

/* Get sweep result fee paid */
LIBDOGECOIN_API uint64_t dogecoin_sweep_result_get_fee_paid(const dogecoin_sweep_result* result);

/* Get sweep result destination address */
LIBDOGECOIN_API const char* dogecoin_sweep_result_get_destination_address(const dogecoin_sweep_result* result);

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_SWEEP_H__
