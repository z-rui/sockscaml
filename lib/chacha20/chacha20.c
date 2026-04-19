#include <caml/misc.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/custom.h>

#include <stdint.h>
#include <string.h>

/* --- Core ChaCha20 Implementation --- */

static inline uint32_t rotate(uint32_t x, unsigned n)
{
    uint32_t hi = x << n;
    uint32_t lo = x >> (32 - n);
    return hi | lo;
}

static inline uint32_t load_le32(const void *p)
{
    const uint8_t *q = (const uint8_t *) p;
    return (uint32_t) q[0] |
          ((uint32_t) q[1] << 8) |
          ((uint32_t) q[2] << 16) |
          ((uint32_t) q[3] << 24);
}

static inline void store_le32(void *p, uint32_t v)
{
    uint8_t *q = (uint8_t *) p;
    q[0] = (uint8_t) v;
    q[1] = (uint8_t) (v >> 8);
    q[2] = (uint8_t) (v >> 16);
    q[3] = (uint8_t) (v >> 24);
}

static inline void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *d = rotate((*a += *b) ^ *d, 16);
    *b = rotate(*b ^ (*c += *d), 12);
    *d = rotate((*a += *b) ^ *d, 8);
    *b = rotate(*b ^ (*c += *d), 7);
}

static void chacha20_core(uint32_t x[16], const uint32_t in[16]) {
    int i;
    memcpy(x, in, 64);

    for (i = 0; i < 10; i++) {
        /* column round */
        qr(&x[0], &x[4], &x[8], &x[12]);
        qr(&x[1], &x[5], &x[9], &x[13]);
        qr(&x[2], &x[6], &x[10], &x[14]);
        qr(&x[3], &x[7], &x[11], &x[15]);
        /* diagonal round */
        qr(&x[0], &x[5], &x[10], &x[15]);
        qr(&x[1], &x[6], &x[11], &x[12]);
        qr(&x[2], &x[7], &x[8], &x[13]);
        qr(&x[3], &x[4], &x[9], &x[14]);
    }
}

static void chacha20_block(uint8_t out[64], const uint32_t in[16]) {
    int i;
    uint32_t x[16];
    chacha20_core(x, in);
    for (i = 0; i < 16; i++) {
        store_le32(out + (i * 4), x[i] + in[i]);
    }
}

/* --- Opaque Context Structure --- */

struct chacha20_ctx {
    uint32_t state[16];     /* Internal state (Constants, Key, Counter, Nonce) */
    uint8_t  keystream[64]; /* Current block of generated keystream */
    uint32_t pos;           /* Position in keystream (in bytes, 0-63) */
};

#define Ctx_val(v) ((struct chacha20_ctx *) Data_custom_val(v))

static struct custom_operations chacha20_ops = {
    "sockscaml.chacha20",
    custom_finalize_default,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default,
    custom_compare_ext_default,
    custom_fixed_length_default
};

/* --- OCaml Bindings --- */

CAMLprim value c_chacha20_create(value v_key, value v_nonce)
{
    CAMLparam2(v_key, v_nonce);
    value v_ctx = caml_alloc_custom(&chacha20_ops, sizeof(struct chacha20_ctx), 0, 1);
    struct chacha20_ctx *ctx = Ctx_val(v_ctx);
    const uint8_t *key = (const uint8_t *) String_val(v_key);
    const uint8_t *nonce = (const uint8_t *) String_val(v_nonce);
    mlsize_t nonce_len = caml_string_length(v_nonce);

    /* Constants */
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    /* Key */
    for (int i = 0; i < 8; i++) ctx->state[4 + i] = load_le32(key + i * 4);
    /* Counter & Nonce */
    ctx->state[12] = 0;
    switch (nonce_len) {
    case 8:
        ctx->state[13] = 0;
        for (int i = 0; i < 2; i++) ctx->state[14 + i] = load_le32(nonce + i * 4);
        break;
    case 12:
        for (int i = 0; i < 3; i++) ctx->state[13 + i] = load_le32(nonce + i * 4);
        break;
    case 16:
        for (int i = 0; i < 4; i++) ctx->state[12 + i] = load_le32(nonce + i * 4);
        break;
    default:
        caml_invalid_argument("invalid nonce size");
    }

    ctx->pos = 0;
    CAMLreturn(v_ctx);
}

CAMLprim value c_hchacha20(value v_key, value v_nonce)
{
    CAMLparam2(v_key, v_nonce);
    uint32_t state[16];
    uint32_t x[16];
    const uint8_t *key = (const uint8_t *) String_val(v_key);
    const uint8_t *nonce = (const uint8_t *) String_val(v_nonce);

    /* Constants */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    /* Key */
    for (int i = 0; i < 8; i++) state[4 + i] = load_le32(key + i * 4);
    /* Nonce */
    for (int i = 0; i < 4; i++) state[12 + i] = load_le32(nonce + i * 4);

    chacha20_core(x, state);

    value v_res = caml_alloc_string(32);
    uint8_t *res = (uint8_t *) Bytes_val(v_res);
    store_le32(res + 0, x[0]);
    store_le32(res + 4, x[1]);
    store_le32(res + 8, x[2]);
    store_le32(res + 12, x[3]);
    store_le32(res + 16, x[12]);
    store_le32(res + 20, x[13]);
    store_le32(res + 24, x[14]);
    store_le32(res + 28, x[15]);

    CAMLreturn(v_res);
}

CAMLprim value c_chacha20_get_counter(value v_ctx)
{
    return caml_copy_int32(Ctx_val(v_ctx)->state[12]);
}

CAMLprim value c_chacha20_set_counter(value v_ctx, value v_ctr)
{
    Ctx_val(v_ctx)->state[12] = Int32_val(v_ctr);
    Ctx_val(v_ctx)->pos = 0; /* Resetting counter invalidates current keystream block */
    return Val_unit;
}

/* Returns 0 on success, 1 on CounterOverflow */
CAMLprim value c_chacha20_crypt(value v_ctx, value v_buf, value v_off, value v_len)
{
    struct chacha20_ctx *ctx = Ctx_val(v_ctx);
    uint8_t *buf = Caml_ba_data_val(v_buf) + Long_val(v_off);
    intnat len = Long_val(v_len);
    uint8_t *ks8 = ctx->keystream;

    /* 1. Consume remaining keystream from buffer */
    while (len > 0 && ctx->pos > 0) {
        *buf++ ^= ks8[ctx->pos++];
        ctx->pos &= 63;
        len--;
    }

    /* 2. Process full blocks */
    while (len >= 64) {
        if (ctx->state[12] == 0xFFFFFFFF) return Val_int(1);

        chacha20_block(ctx->keystream, ctx->state);
        ctx->state[12]++;

        for (int i = 0; i < 64; i++) buf[i] ^= ks8[i];

        buf += 64;
        len -= 64;
    }

    /* 3. Handle trailing bytes */
    if (len > 0) {
        if (ctx->state[12] == 0xFFFFFFFF) return Val_int(1);

        chacha20_block(ctx->keystream, ctx->state);
        ctx->state[12]++;

        for (int i = 0; i < len; i++) {
            buf[i] ^= ks8[ctx->pos++];
        }
    }

    return Val_int(0);
}
