/*
 * RFC 7914 scrypt (Colin Percival reference), for BIP38 KDF.
 * Derived from public-domain/crypto_scrypt reference (Tarsnap / libscrypt style).
 */

#include <dogecoin/scrypt_bip38.h>
#include <dogecoin/scrypt.h>
#include <dogecoin/sha2.h>
#include <dogecoin/mem.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void blkxor(uint32_t* dest, const uint32_t* src, size_t len)
{
    size_t i;
    for (i = 0; i < len / 4; i++)
        dest[i] ^= src[i];
}

static void salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    size_t i;

    memcpy(x, B, 64);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);

        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);

        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);

        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);

        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);

        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);

        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);

        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
#undef R
    }
    for (i = 0; i < 16; i++)
        B[i] += x[i];
}

static void blockmix_salsa8(uint32_t* Bin, uint32_t* Bout, uint32_t* X, size_t r)
{
    size_t i;

    memcpy(X, &Bin[(2 * r - 1) * 16], 64);

    for (i = 0; i < 2 * r; i += 2) {
        blkxor(X, &Bin[i * 16], 64);
        salsa20_8(X);

        memcpy(&Bout[i * 8], X, 64);

        blkxor(X, &Bin[i * 16 + 16], 64);
        salsa20_8(X);

        memcpy(&Bout[i * 8 + r * 16], X, 64);
    }
}

static uint64_t integerify(uint32_t* B, size_t r)
{
    const uint32_t* X = B + (2 * r - 1) * 16;
    return (((uint64_t)(X[1]) << 32) + X[0]);
}

static void smix(uint8_t* B, size_t r, uint64_t N, uint32_t* V, uint32_t* XY)
{
    uint32_t* X = XY;
    uint32_t* Y = &XY[32 * r];
    uint32_t* Z = &XY[64 * r];
    uint64_t i;
    uint64_t j;
    size_t k;

    for (k = 0; k < 32 * r; k++)
        X[k] = le32dec(&B[4 * k]);

    for (i = 0; i < N; i += 2) {
        memcpy(&V[i * (32 * r)], X, 128 * r);
        blockmix_salsa8(X, Y, Z, r);

        memcpy(&V[(i + 1) * (32 * r)], Y, 128 * r);
        blockmix_salsa8(Y, X, Z, r);
    }

    for (i = 0; i < N; i += 2) {
        j = integerify(X, r) & (N - 1);

        blkxor(X, &V[j * (32 * r)], 128 * r);
        blockmix_salsa8(X, Y, Z, r);

        j = integerify(Y, r) & (N - 1);

        blkxor(Y, &V[j * (32 * r)], 128 * r);
        blockmix_salsa8(Y, X, Z, r);
    }

    for (k = 0; k < 32 * r; k++)
        le32enc(&B[4 * k], X[k]);
}

static void* alloc_aligned(size_t size, size_t align, void** base_out)
{
    void* p = malloc(size + align - 1);
    *base_out = p;
    if (!p)
        return NULL;
    return (void*)(((uintptr_t)p + align - 1) & ~(uintptr_t)(align - 1));
}

dogecoin_bool dogecoin_scrypt(
    const uint8_t* passwd,
    size_t passwdlen,
    const uint8_t* salt,
    size_t saltlen,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    uint8_t* buf,
    size_t buflen)
{
    void *B0 = NULL, *V0 = NULL, *XY0 = NULL;
    uint8_t* B;
    uint32_t* V;
    uint32_t* XY;
    uint32_t i;

    if (buflen > (((uint64_t)1 << 32) - 1) * 32)
        return false;
    if ((uint64_t)r * (uint64_t)p >= (1ULL << 30))
        return false;
    if (r == 0 || p == 0)
        return false;
    if (((N & (N - 1)) != 0) || (N < 2))
        return false;
    if (r > SIZE_MAX / 128 / p)
        return false;
    if (N > SIZE_MAX / 128 / r)
        return false;

    B = (uint8_t*)alloc_aligned(128 * r * p + 63, 64, &B0);
    if (!B0)
        return false;
    XY = (uint32_t*)alloc_aligned((256 * r + 64) + 63, 64, &XY0);
    if (!XY0) {
        free(B0);
        return false;
    }
    V = (uint32_t*)alloc_aligned(128 * r * N + 63, 64, &V0);
    if (!V0) {
        free(XY0);
        free(B0);
        return false;
    }

    pbkdf2_hmac_sha256(passwd, (int)passwdlen, salt, (int)saltlen, 1, B, (int)(p * 128 * r));

    for (i = 0; i < p; i++) {
        smix(&B[i * 128 * r], r, N, V, XY);
    }

    pbkdf2_hmac_sha256(passwd, (int)passwdlen, B, (int)(p * 128 * r), 1, buf, (int)buflen);

    dogecoin_mem_zero(V0, 128 * r * N + 63);
    dogecoin_mem_zero(XY0, (256 * r + 64) + 63);
    dogecoin_mem_zero(B0, 128 * r * p + 63);
    free(V0);
    free(XY0);
    free(B0);
    return true;
}
