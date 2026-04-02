/*
 * RFC 7914 scrypt for BIP38 (N=16384, r=8, p=8, dkLen=64).
 * Copyright 2009 Colin Percival (reference implementation); adapted for libdogecoin.
 */

#ifndef __LIBDOGECOIN_SCRYPT_BIP38_H__
#define __LIBDOGECOIN_SCRYPT_BIP38_H__

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/** BIP38 scrypt KDF. Returns true on success. */
LIBDOGECOIN_API dogecoin_bool dogecoin_scrypt(
    const uint8_t* passwd,
    size_t passwdlen,
    const uint8_t* salt,
    size_t saltlen,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    uint8_t* buf,
    size_t buflen);

LIBDOGECOIN_END_DECL

#endif
