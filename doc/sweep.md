# Paper Wallet Sweeping and BIP38 Support

This document describes the paper wallet sweeping functionality and BIP38 private key encryption support added to libdogecoin.

## Including the Headers

To use the BIP38 and sweep functionality, you need to include the specific headers:

```c
#include <dogecoin/libdogecoin.h>  // Core libdogecoin functionality
#include <dogecoin/bip38.h>        // BIP38 encryption/decryption (optional)
#include <dogecoin/sweep.h>        // Paper wallet sweeping (optional)
```

**Note**: The BIP38 and sweep functionality are separate from the core libdogecoin library and must be explicitly included when needed.

## Overview

The paper wallet sweeping functionality allows users to transfer funds from paper wallets (including BIP38 encrypted ones) to regular wallet addresses. This is commonly known as "sweeping" because it moves all funds from the paper wallet in a single transaction.

## BIP38 Support

BIP38 (Bitcoin Improvement Proposal 38) defines a standard for encrypting private keys with a passphrase. This provides additional security for paper wallets.

### Key Features

- **Private Key Encryption**: Encrypt private keys with a passphrase using scrypt
- **Address Hash Verification**: Verify that the encrypted key matches the expected address
- **Compression Support**: Support for both compressed and uncompressed public keys
- **Lot/Sequence Support**: Support for lot and sequence numbers (future enhancement)

### BIP38 Functions

```c
// Encrypt a private key
dogecoin_bool dogecoin_bip38_encrypt(
    const uint8_t* private_key,
    const char* passphrase,
    const char* address,
    dogecoin_bool compressed,
    char* encrypted_key_out,
    size_t* encrypted_key_size
);

// Decrypt a private key
dogecoin_bool dogecoin_bip38_decrypt(
    const char* encrypted_key,
    const char* passphrase,
    uint8_t* private_key_out,
    dogecoin_bool* compressed_out
);

// Validate BIP38 encrypted key
dogecoin_bool dogecoin_bip38_is_valid(const char* encrypted_key);
```

## Paper Wallet Sweeping

The sweeping functionality provides a complete API for transferring funds from paper wallets to regular addresses.

### Paper Wallet Structure

```c
typedef struct {
    char* private_key_wif;           // WIF format private key
    char* private_key_hex;           // Hex format private key
    char* encrypted_private_key;     // BIP38 encrypted private key
    char* passphrase;                // Passphrase for BIP38 decryption
    char* address;                   // Dogecoin address
    dogecoin_bool compressed;        // Whether public key is compressed
    dogecoin_bool is_encrypted;      // Whether private key is encrypted
    const dogecoin_chainparams* chain_params; // Chain parameters
} dogecoin_paper_wallet;
```

### Sweep Options

```c
typedef struct {
    char* destination_address;       // Address to sweep funds to
    uint64_t fee_per_byte;          // Fee in satoshis per byte
    uint64_t min_fee;               // Minimum fee in satoshis
    uint64_t max_fee;               // Maximum fee in satoshis
    dogecoin_bool use_rbf;          // Replace-by-fee support
    uint32_t locktime;              // Transaction locktime
    const dogecoin_chainparams* chain_params; // Chain parameters
} dogecoin_sweep_options;
```

### Sweep Result

```c
typedef struct {
    dogecoin_bool success;          // Whether sweep was successful
    char* error_message;            // Error message if failed
    char* transaction_hex;          // Raw transaction hex
    char* transaction_id;           // Transaction ID
    uint64_t amount_swept;          // Amount swept in satoshis
    uint64_t fee_paid;              // Fee paid in satoshis
    char* destination_address;      // Destination address
} dogecoin_sweep_result;
```

## Usage Examples

### Creating a Paper Wallet from WIF

```c
#include <dogecoin/sweep.h>
#include <dogecoin/chainparams.h>

const dogecoin_chainparams* chain = &dogecoin_chainparams_main;
dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();

const char* wif = "6KQj9B2BwtZLrXM85t2QfC76NybA8FXJq4VWZvdfW6opQH4iQuz";
if (dogecoin_paper_wallet_set_wif(wallet, wif, chain)) {
    char address[DOGECOIN_ADDRESS_MAX_LENGTH];
    dogecoin_paper_wallet_get_address(wallet, address, sizeof(address));
    printf("Paper wallet address: %s\n", address);
}

dogecoin_paper_wallet_free(wallet);
```

### Creating a Paper Wallet from BIP38 Encrypted Key

```c
const char* encrypted_key = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2oGDS";
const char* passphrase = "my_secure_passphrase";

dogecoin_paper_wallet* wallet = dogecoin_paper_wallet_new();
if (dogecoin_paper_wallet_set_encrypted(wallet, encrypted_key, passphrase, chain)) {
    printf("Successfully created encrypted paper wallet\n");
}
```

### Setting Up Sweep Options

```c
dogecoin_sweep_options* options = dogecoin_sweep_options_new(chain);
dogecoin_sweep_options_set_destination(options, "D7Y55vD8nNtW7VnT9Xr6Qc4vB8hN3jK2mP");
dogecoin_sweep_options_set_fee(options, 1000, 500, 2000); // 0.01 DOGE per KB, min 0.005 DOGE, max 0.02 DOGE
```

### Sweeping a Paper Wallet

```c
dogecoin_sweep_result* result = dogecoin_sweep_paper_wallet(wallet, options);
if (result->success) {
    printf("Sweep successful! Transaction ID: %s\n", result->transaction_id);
    printf("Amount swept: %llu satoshis\n", result->amount_swept);
} else {
    printf("Sweep failed: %s\n", result->error_message);
}
dogecoin_sweep_result_free(result);
```

## BIP38 Encryption Example

```c
#include <dogecoin/bip38.h>

// Generate a private key
dogecoin_key key;
dogecoin_privkey_gen(&key);

// Get the address
dogecoin_pubkey pubkey;
dogecoin_pubkey_from_key(&key, &pubkey);
char address[DOGECOIN_ADDRESS_MAX_LENGTH];
dogecoin_pubkey_getaddr_p2pkh(&pubkey, chain, address);

// Encrypt the private key
char encrypted_key[BIP38_ENCRYPTED_KEY_LENGTH + 1];
size_t encrypted_size = sizeof(encrypted_key);
const char* passphrase = "my_secure_passphrase";

if (dogecoin_bip38_encrypt(key.privkey, passphrase, address, true, encrypted_key, &encrypted_size)) {
    printf("Encrypted private key: %s\n", encrypted_key);
}

// Decrypt the private key
uint8_t decrypted_key[DOGECOIN_ECKEY_PKEY_LENGTH];
dogecoin_bool compressed;
if (dogecoin_bip38_decrypt(encrypted_key, passphrase, decrypted_key, &compressed)) {
    printf("Successfully decrypted private key\n");
}
```

## Security Considerations

1. **Passphrase Security**: Use strong, unique passphrases for BIP38 encryption
2. **Private Key Handling**: Always clear private keys from memory after use
3. **Address Verification**: Always verify that the decrypted key matches the expected address
4. **Fee Management**: Set appropriate fees to ensure transaction confirmation
5. **UTXO Validation**: Verify UTXO data before attempting to sweep

## Error Handling

All functions return appropriate error codes and provide error messages when operations fail. Always check return values and handle errors appropriately:

```c
if (!dogecoin_paper_wallet_set_wif(wallet, wif, chain)) {
    printf("Failed to set up paper wallet\n");
    // Handle error
}
```

## Testing

The implementation includes comprehensive tests in `test/sweep_tests.c`. Run the tests to verify functionality:

```bash
gcc -o sweep_tests test/sweep_tests.c src/sweep.c src/bip38.c -Iinclude -ldogecoin
./sweep_tests
```

## Future Enhancements

1. **UTXO Querying**: Integration with blockchain APIs to query UTXOs
2. **Transaction Broadcasting**: Direct transaction broadcasting to the network
3. **Fee Estimation**: Dynamic fee estimation based on network conditions
4. **Batch Sweeping**: Sweep multiple paper wallets in a single transaction
5. **Lot/Sequence Support**: Full BIP38 lot/sequence number support

## API Reference

For complete API documentation, see:
- `include/dogecoin/bip38.h` - BIP38 encryption/decryption functions
- `include/dogecoin/sweep.h` - Paper wallet sweeping functions
- `test/sweep_tests.c` - Comprehensive test suite
- `contrib/examples/sweep_example.c` - Usage examples
