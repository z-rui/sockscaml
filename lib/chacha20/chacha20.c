#include <caml/misc.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>
#include <caml/memory.h>
#include <caml/fail.h>

#include <stdint.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#include "byteswap.h"
#endif

static inline uint32_t rotate(uint32_t x, unsigned n)
{
    uint32_t hi = x << n;
    uint32_t lo = x >> (32 - n);
    return hi | lo;
}

static inline uint32_t load_le32(const uint32_t *x)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return bswap_32(*x);
#else
    return *x;
#endif
}

static inline void store_le32(uint32_t *x, uint32_t v)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    *x = bswap_32(v);
#else
    *x = v;
#endif
}

static inline void qr(uint32_t *pa, uint32_t *pb, uint32_t *pc, uint32_t *pd) {
    uint32_t a = load_le32(pa);
    uint32_t b = load_le32(pb);
    uint32_t c = load_le32(pc);
    uint32_t d = load_le32(pd);
    d = rotate((a += b) ^ d, 16);
    b = rotate(b ^ (c += d), 12);
    d = rotate((a += b) ^ d, 8);
    b = rotate(b ^ (c += d), 7);
    store_le32(pa, a);
    store_le32(pb, b);
    store_le32(pc, c);
    store_le32(pd, d);
}

static void chacha20_block(uint32_t *x) {
    int i;
    for (i = 0; i < 10; i++) {
        /* column round */
        qr(x + 0, x + 4, x + 8, x + 12);
        qr(x + 1, x + 5, x + 9, x + 13);
        qr(x + 2, x + 6, x + 10, x + 14);
        qr(x + 3, x + 7, x + 11, x + 15);
        /* diagonal round */
        qr(x + 0, x + 5, x + 10, x + 15);
        qr(x + 1, x + 6, x + 11, x + 12);
        qr(x + 2, x + 7, x + 8, x + 13);
        qr(x + 3, x + 4, x + 9, x + 14);
    }
}

CAMLprim value c_chacha20_init(value v_output, value v_key, value v_nonce)
{
    CAMLparam3(v_output, v_key, v_nonce);

    // CAML allocation is always 4B aligned
    uint32_t *output = (uint32_t *) Caml_ba_data_val(v_output);
    const uint8_t *key = Bytes_val(v_key);
    const uint8_t *nonce = Bytes_val(v_nonce);
    mlsize_t nonce_len = caml_string_length(v_nonce);

    memcpy(output, "expand 32-byte k", 16);
    memcpy(output + 4, key, 32);
    switch (nonce_len) {
    case 8:
        output[12] = output[13] = 0;
        memcpy(output + 14, nonce, 8);
        break;
    case 12:
        output[12] = 0;
        memcpy(output + 13, nonce, 12);
        break;
    case 16:
        memcpy(output + 12, nonce, 16);
        break;
    default:
        caml_failwith("invalid nonce size");
        break;
    }
    CAMLreturn(Val_unit);
}

CAMLprim value c_chacha20_block(value v_output)
{
    CAMLparam1(v_output);

    chacha20_block((uint32_t *) Caml_ba_data_val(v_output));
    CAMLreturn(Val_unit);
}

static inline void block_add(uint32_t *restrict dst, const uint32_t *restrict src)
{
    intnat i;

    for (i = 0; i < 16; i++)
        dst[i] += src[i];
}

CAMLprim value c_chacha20_block_add(value v_dst, value v_src)
{
    CAMLparam2(v_dst, v_src);
    uint32_t *dst = (uint32_t *) Caml_ba_data_val(v_dst);
    const uint32_t *src = (const uint32_t *) Caml_ba_data_val(v_src);

    memcpy(dst, src, 64);
    chacha20_block(dst);
    block_add(dst, src);
    CAMLreturn(Val_unit);
}

static inline void memxor(uint8_t *restrict dst, const uint8_t *restrict src, intnat n)
{
    intnat i;

    for (i = 0; i < n; i++)
        dst[i] ^= src[i];
}

CAMLprim value c_chacha20_xorblit(value v_src, value v_srcpos, value v_dst, value v_dstpos, value v_n)
{
    CAMLparam5(v_src, v_srcpos, v_dst, v_dstpos, v_n);
    uint8_t *dst = Caml_ba_data_val(v_dst) + Long_val(v_dstpos);
    const uint8_t *src = Caml_ba_data_val(v_src) + Long_val(v_srcpos);
    intnat n = Long_val(v_n);
    memxor(dst, src, n);
    CAMLreturn(Val_unit);
}

CAMLprim value c_chacha20_loopbody(value v_out, value v_off, value v_dst, value v_src)
{
    CAMLparam4(v_out, v_off, v_dst, v_src);
    uint8_t *out = Caml_ba_data_val(v_out) + Long_val(v_off);
    uint32_t *dst = (uint32_t *) Caml_ba_data_val(v_dst);
    uint32_t *src = (uint32_t *) Caml_ba_data_val(v_src);
    uint32_t *ctr = &src[12];

    memcpy(dst, src, 64);
    chacha20_block(dst);
    block_add(dst, src);
    memxor(out, (uint8_t *) dst, 64);
    store_le32(ctr, load_le32(ctr) + 1);
    CAMLreturn(Val_unit);
}
