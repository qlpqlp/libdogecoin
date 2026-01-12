/*

 The MIT License (MIT)

 Copyright (c) 2024 edtubbs, bluezr
 Copyright (c) 2024 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include <dogecoin/rest.h>

#include <dogecoin/blockchain.h>
#include <dogecoin/koinu.h>
#include <dogecoin/headersdb_file.h>
#include <dogecoin/spv.h>
#include <dogecoin/wallet.h>

#define TIMESTAMP_MAX_LEN 32

/**
 * This function is called when an http request is received
 * It handles the request and sends a response
 *
 * @param req the request
 * @param arg the client
 *
 * @return Nothing.
 */
void dogecoin_http_request_cb(struct evhttp_request *req, void *arg) {
    dogecoin_spv_client* client = (dogecoin_spv_client*)arg;
    dogecoin_wallet* wallet = (dogecoin_wallet*)client->sync_transaction_ctx;
    if (!wallet) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    const struct evhttp_uri* uri = evhttp_request_get_evhttp_uri(req);
    const char* path = evhttp_uri_get_path(uri);

    struct evbuffer *evb = NULL;
    evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        return;
    }

    if (strcmp(path, "/getBalance") == 0) {
        int64_t balance = dogecoin_wallet_get_balance(wallet);
        char balance_str[32] = {0};
        koinu_to_coins_str(balance, balance_str);
        evbuffer_add_printf(evb, "Wallet balance: %s\n", balance_str);
    } else if (strcmp(path, "/getAddresses") == 0) {
        vector_t* addresses = vector_new(10, dogecoin_free);
        dogecoin_wallet_get_addresses(wallet, addresses);
        for (unsigned int i = 0; i < addresses->len; i++) {
            char* address = vector_idx(addresses, i);
            evbuffer_add_printf(evb, "address: %s\n", address);
        }
        vector_free(addresses, true);
    } else if (strcmp(path, "/getTransactions") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64 = 0;

        if (HASH_COUNT(wallet->utxos) > 0) {
            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                if (!utxo->spendable) {
                    // For spent UTXOs
                    evbuffer_add_printf(evb, "%s\n", "----------------------");
                    evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof(utxo->txid)));
                    evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                    evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                    evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                    evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                    evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                    evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                    evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                    evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                    wallet_total_u64 += coins_to_koinu_str(utxo->amount);
                }
            }
        }

        // Convert and print totals for spent UTXOs.
        koinu_to_coins_str(wallet_total_u64, wallet_total);
        evbuffer_add_printf(evb, "Spent Balance: %s\n", wallet_total);
    } else if (strcmp(path, "/getUTXOs") == 0) {
        char wallet_total[21];
        dogecoin_mem_zero(wallet_total, 21);
        uint64_t wallet_total_u64_unspent = 0;

        dogecoin_utxo* utxo;
        dogecoin_utxo* tmp;

        HASH_ITER(hh, wallet->utxos, utxo, tmp) {
            if (utxo->spendable) {
                // For unspent UTXOs
                evbuffer_add_printf(evb, "----------------------\n");
                evbuffer_add_printf(evb, "Unspent UTXO:\n");
                evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof(utxo->txid)));
                evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
                wallet_total_u64_unspent += coins_to_koinu_str(utxo->amount);
            }
        }

        // Convert and print totals for unspent UTXOs.
        koinu_to_coins_str(wallet_total_u64_unspent, wallet_total);
        evbuffer_add_printf(evb, "Total Unspent: %s\n", wallet_total);
    } else if (strcmp(path, "/getWallet") == 0) {
        // Get the wallet file
        FILE* file = wallet->dbfile;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Wallet file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the wallet file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the wallet file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (result != (size_t)file_size) {
            free(buffer);
            evbuffer_free(evb);
            evhttp_send_error(req, HTTP_INTERNAL, "Failed to read wallet file");
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getHeaders") == 0) {
        // Get the headers file
        dogecoin_headers_db* headers_db = (dogecoin_headers_db *)(client->headers_db_ctx);
        FILE* file = headers_db->headers_tree_file;
        if (file == NULL) {
            evhttp_send_error(req, HTTP_NOTFOUND, "Headers file not found");
            evbuffer_free(evb);
            return;
        }

        // Get the size of the headers file
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        // Read the headers file into a buffer
        char* buffer = malloc(file_size);
        if (buffer == NULL) {
            evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
            evbuffer_free(evb);
            return;
        }
        size_t result = fread(buffer, 1, file_size, file);
        if (result !=  (size_t)file_size) {
            free(buffer);
            evbuffer_free(evb);
            evhttp_send_error(req, HTTP_INTERNAL, "Failed to read headers file");
            return;
        }

        // Add the buffer to the response buffer
        evbuffer_add(evb, buffer, file_size);

        // Set the Content-Type header to "application/octet-stream" for binary data
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/octet-stream");

        // Clean up
        free(buffer);
    } else if (strcmp(path, "/getChaintip") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        evbuffer_add_printf(evb, "Chain tip: %d\n", tip->height);
    } else if (strcmp(path, "/getTimestamp") == 0) {
        dogecoin_blockindex* tip = client->headers_db->getchaintip(client->headers_db_ctx);
        char s[TIMESTAMP_MAX_LEN];
        time_t t = tip->header.timestamp;
        struct tm *p = localtime(&t);
        strftime(s, sizeof(s), "%F %T", p);
        evbuffer_add_printf(evb, "%s\n", s);
    } else if (strcmp(path, "/getLastBlockInfo") == 0) {
        uint64_t size = client->last_block_size;
        uint64_t tx_count = client->last_block_tx_count;
        uint64_t total_tx_size = client->last_block_total_tx_size;

        evbuffer_add_printf(evb, "Block size: %lu\n", size);
        evbuffer_add_printf(evb, "Tx count: %lu\n", tx_count);
        evbuffer_add_printf(evb, "Total tx size: %lu\n", total_tx_size);
    } else if (strcmp(path, "/getRawTx") == 0) {
        // Return ASCII raw tx by txid: ?txid=<64-hex big-endian>
        const char* query = evhttp_uri_get_query(uri);
        if (!query) { evhttp_send_error(req, HTTP_BADREQUEST, "missing ?txid"); evbuffer_free(evb); return; }

        // extract txid=... up to '&'
        const char* p = strstr(query, "txid=");
        if (!p) { evhttp_send_error(req, HTTP_BADREQUEST, "missing txid param"); evbuffer_free(evb); return; }
        p += 5;
        char txid_hex[65]; size_t n = 0;
        while (p[n] && p[n] != '&' && n < 64) { txid_hex[n] = p[n]; n++; }
        txid_hex[n] = '\0';
        if (n != 64) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid length"); evbuffer_free(evb); return; }

        //parse big-endian hex -> bytes, then convert to little-endian for cache compare
        uint8_t txid_be[32]; size_t outlen = 0;
        utils_hex_to_bin(txid_hex, txid_be, 64, &outlen);
        if (outlen != 32) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid hex"); evbuffer_free(evb); return; }
        uint8_t txid_le[32];
        for (int i = 0; i < 32; ++i) txid_le[i] = txid_be[31 - i];

        int found = 0;
        for (unsigned int i = 0; i < wallet->vec_wtxes->len; i++) {
            dogecoin_wtx* wtx = vector_idx(wallet->vec_wtxes, i);
            if (!wtx || !wtx->tx) continue;
            if (memcmp(wtx->tx_hash_cache, txid_le, 32) != 0) continue;

            // serialize & hex-encode the tx
            cstring* ser = cstr_new_sz(1024);
            if (!ser) { evhttp_send_error(req, HTTP_INTERNAL, "oom"); evbuffer_free(evb); return; }
            dogecoin_tx_serialize(ser, wtx->tx);
            char* hexout = (char*)malloc(ser->len * 2 + 1);
            if (!hexout) { cstr_free(ser, true); evhttp_send_error(req, HTTP_INTERNAL, "oom"); evbuffer_free(evb); return; }
            utils_bin_to_hex((unsigned char*)ser->str, ser->len, hexout);
            cstr_free(ser, true);

            evbuffer_add_printf(evb, "%s\n", hexout);
            free(hexout);
            found = 1;
            break;
        }

        if (!found) { evhttp_send_error(req, HTTP_NOTFOUND, "tx not found"); evbuffer_free(evb); return; }

    } else if (strcmp(path, "/viewTx") == 0) {
        // Print UTXO-style info for a single tx by txid; optional ?vout=<n> or ?n=<n> to filter
        const char* query = evhttp_uri_get_query(uri);
        if (!query) { evhttp_send_error(req, HTTP_BADREQUEST, "missing ?txid"); evbuffer_free(evb); return; }

        // extract txid
        const char* p = strstr(query, "txid=");
        if (!p) { evhttp_send_error(req, HTTP_BADREQUEST, "missing txid param"); evbuffer_free(evb); return; }
        p += 5;
        char txid_hex[65]; size_t n = 0;
        while (p[n] && p[n] != '&' && n < 64) { txid_hex[n] = p[n]; n++; }
        txid_hex[n] = '\0';
        if (n != 64) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid length"); evbuffer_free(evb); return; }

        // parse optional vout / n
        int have_vout = 0, want_vout = 0;
        const char* pv = strstr(query, "vout=");
        if (!pv) pv = strstr(query, "n=");
        if (pv) {
            pv += (pv[1] == 'o') ? 5 : 2; // 'vout='=5, 'n='=2
            char numbuf[16]; size_t k = 0;
            while (pv[k] && pv[k] != '&' && k < sizeof(numbuf) - 1) { numbuf[k] = pv[k]; k++; }
            numbuf[k] = '\0';
            want_vout = atoi(numbuf);
            have_vout = 1;
        }

        // utxo->txid bytes are big-endian (display order)
        uint8_t txid_be[32]; size_t outlen = 0;
        utils_hex_to_bin(txid_hex, txid_be, 64, &outlen);
        if (outlen != 32) { evhttp_send_error(req, HTTP_BADREQUEST, "invalid txid hex"); evbuffer_free(evb); return; }

        int found = 0;
        if (HASH_COUNT(wallet->utxos) > 0) {
            dogecoin_utxo* utxo;
            dogecoin_utxo* tmp;
            HASH_ITER(hh, wallet->utxos, utxo, tmp) {
                if (memcmp(utxo->txid, txid_be, 32) != 0) continue;
                if (have_vout && utxo->vout != want_vout) continue;
                found = 1;
                evbuffer_add_printf(evb, "%s\n", "----------------------");
                evbuffer_add_printf(evb, "txid:           %s\n", utils_uint8_to_hex(utxo->txid, sizeof utxo->txid));
                evbuffer_add_printf(evb, "vout:           %d\n", utxo->vout);
                evbuffer_add_printf(evb, "address:        %s\n", utxo->address);
                evbuffer_add_printf(evb, "script_pubkey:  %s\n", utxo->script_pubkey);
                evbuffer_add_printf(evb, "amount:         %s\n", utxo->amount);
                evbuffer_add_printf(evb, "confirmations:  %d\n", utxo->confirmations);
                evbuffer_add_printf(evb, "height:         %d\n", utxo->height);
                evbuffer_add_printf(evb, "spendable:      %d\n", utxo->spendable);
                evbuffer_add_printf(evb, "solvable:       %d\n", utxo->solvable);
            }
        }

        if (!found) {
            evbuffer_add_printf(evb, "No matching UTXOs for txid\n");
        }

    } else {
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
        evbuffer_free(evb);
        return;
    }

    // Set Content-Type header if not already set
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    if (!evhttp_find_header(headers, "Content-Type")) {
        evhttp_add_header(headers, "Content-Type", "text/plain");
    }

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
