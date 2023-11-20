#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
typedef struct Context {
    __m128i state[8];  // state
    size_t sizeM;      // byte length of input data
    size_t sizeAD;     // byte length of associated data
} context;

#define S_NUM 8
#define M_NUM 2
#define BLKSIZE 32
#define NUM_LOOP_FOR_INIT 20

// Z0 = 428a2f98d728ae227137449123ef65cd
#define Z0_3 0x428a2f98
#define Z0_2 0xd728ae22
#define Z0_1 0x71374491
#define Z0_0 0x23ef65cd

// Z1 = b5c0fbcfec4d3b2fe9b5dba58189dbbc
#define Z1_3 0xb5c0fbcf
#define Z1_2 0xec4d3b2f
#define Z1_1 0xe9b5dba5
#define Z1_0 0x8189dbbc

#define enc(m, k) _mm_aesenc_si128(m, k)
#define xor(a, b) _mm_xor_si128(a, b)

#define UPDATE_STATE(X)     \
    tmp7 = S[7];            \
    tmp6 = S[6];            \
    S[7] = xor(S[6], S[0]); \
    S[6] = enc(S[5], S[4]); \
    S[5] = enc(S[4], S[3]); \
    S[4] = xor(S[3], X[1]); \
    S[3] = enc(S[2], S[1]); \
    S[2] = xor(S[1], tmp6); \
    S[1] = enc(S[0], tmp7); \
    S[0] = xor(tmp7, X[0]);

#define LOAD(src, dst)                                \
    dst[0] = _mm_loadu_si128((const __m128i *)(src)); \
    dst[1] = _mm_loadu_si128((const __m128i *)((src) + 16));

#define XOR_STRM(src, dst)                 \
    dst[0] = xor(src[0], enc(S[1], S[5])); \
    dst[1] = xor(src[1], enc(xor(S[0], S[4]), S[2]));

#define STORE(src, dst)                           \
    _mm_storeu_si128((__m128i *)((dst)), src[0]); \
    _mm_storeu_si128((__m128i *)((dst) + 16), src[1]);

#define CAST_U64_TO_M128(v)                                   \
    _mm_set_epi32(0, 0, (((uint64_t)(v)) >> 32) & 0xFFFFFFFF, \
                  (((uint64_t)(v)) >> 0) & 0xFFFFFFFF)

void stream_init(context *ctx, const uint8_t *key, const uint8_t *nonce) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    // Initialize internal state
    S[0] = _mm_loadu_si128((const __m128i *)(key + 16));
    S[1] = _mm_loadu_si128((const __m128i *)(nonce));
    S[2] = _mm_set_epi32(Z0_3, Z0_2, Z0_1, Z0_0);
    S[3] = _mm_set_epi32(Z1_3, Z1_2, Z1_1, Z1_0);
    S[4] = _mm_xor_si128(S[1], S[0]);
    S[5] = _mm_setzero_si128();
    S[6] = _mm_loadu_si128((const __m128i *)(key));
    S[7] = _mm_setzero_si128();
    M[0] = S[2];
    M[1] = S[3];

    // Update local state
    for (size_t i = 0; i < NUM_LOOP_FOR_INIT; ++i) {
        UPDATE_STATE(M)
    }

    // Update context
    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeM = 0;
    ctx->sizeAD = 0;
}

size_t stream_proc_ad(context *ctx, const uint8_t *ad, size_t size) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    // Copy state from context
    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    // Update local state with associated data
    size_t proc_size = 0;
    for (size_t size2 = size / BLKSIZE * BLKSIZE; proc_size < size2;
         proc_size += BLKSIZE) {
        LOAD(ad + proc_size, M);
        UPDATE_STATE(M);
    }

    // Update context
    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeAD += proc_size;

    return proc_size;
}

size_t stream_enc(context *ctx, uint8_t *dst, const uint8_t *src, size_t size) {
    __m128i S[S_NUM], M[M_NUM], C[M_NUM], tmp7, tmp6;

    // Copy state from context
    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    // Generate and output ciphertext
    // Update internal state with plaintext
    size_t proc_size = 0;
    for (size_t size2 = size / BLKSIZE * BLKSIZE; proc_size < size2;
         proc_size += BLKSIZE) {
        LOAD(src + proc_size, M);
        XOR_STRM(M, C);
        STORE(C, dst + proc_size);
        UPDATE_STATE(M);
    }

    // Update context
    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeM += proc_size;

    return proc_size;
}

size_t stream_dec(context *ctx, uint8_t *dst, const uint8_t *src, size_t size) {
    __m128i S[S_NUM], M[M_NUM], C[M_NUM], tmp7, tmp6;

    // Copy state from context
    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    // Generate and output plaintext
    // Update internal state with plaintext
    size_t proc_size = 0;
    for (size_t size2 = size / BLKSIZE * BLKSIZE; proc_size < size2;
         proc_size += BLKSIZE) {
        LOAD(src + proc_size, C);
        XOR_STRM(C, M);
        STORE(M, dst + proc_size);
        UPDATE_STATE(M);
    }

    // Update context
    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeM += proc_size;

    return proc_size;
}

void stream_finalize(context *ctx, uint8_t *tag) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    // Copy state from context
    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    // set M[0] to bit length of processed AD
    // set M[1] to bit length of processed M
    M[0] = CAST_U64_TO_M128((uint64_t)ctx->sizeAD << 3);
    M[1] = CAST_U64_TO_M128((uint64_t)ctx->sizeM << 3);

    // Update internal state
    for (size_t i = 0; i < NUM_LOOP_FOR_INIT; ++i) {
        UPDATE_STATE(M)
    }

    // Generate tag by XORing all S[i]s
    for (size_t i = 1; i < S_NUM; ++i) {
        S[0] = _mm_xor_si128(S[0], S[i]);
    }

    // Output tag
    _mm_store_si128((__m128i *)tag, S[0]);
}

void print_m128i(FILE *file, const __m128i m) {
    uint8_t *p = (uint8_t *)&m;
    for (int i = 0; i < 16; i++) {
        fprintf(file, "%d ", p[i]);
    }
    fprintf(file, "\n");
}

int main() {
    FILE *output = fopen("output.txt", "w");
    if (!output) {
        perror("Failed to open output file");
        return 1;
    }

    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    uint8_t ad[32] = {0};
    uint8_t src[32] = {0};
    uint8_t dst[32] = {0};
    uint8_t tag[16] = {0};
    context ctx;

    fprintf(output, "Key is: \n");
    for (int i = 0; i < 32; i++) {
        key[i] = rand() % 256;
        fprintf(output, "%d ", key[i]);
    }
    fprintf(output, "\nNonce is: \n");
    for (int i = 0; i < 16; i++) {
        nonce[i] = rand() % 256;
        fprintf(output, "%d ", nonce[i]);
    }
    fprintf(output, "\nAssociated data is: \n");
    for (int i = 0; i < 32; i++) {
        ad[i] = rand() % 256;
        fprintf(output, "%d ", ad[i]);
    }
    fprintf(output, "\nPlaintext is: \n");
    for (int i = 0; i < 32; i++) {
        src[i] = rand() % 256;
        fprintf(output, "%d ", src[i]);
    }

    stream_init(&ctx, key, nonce);
    fprintf(output, "\nThe initial state is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    stream_proc_ad(&ctx, ad, 32);
    fprintf(output, "\nState after processing associated data is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    stream_enc(&ctx, dst, src, 32);
    fprintf(output, "\nState after encrypting source data is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    fprintf(output, "\nCiphertext is: \n");
    for (int i = 0; i < 32; i++) {
        fprintf(output, "%d ", dst[i]);
    }

    stream_finalize(&ctx, tag);
    fprintf(output, "\nState after finalizing is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    fprintf(output, "\nTag is: \n");
    for (int i = 0; i < 16; i++) {
        fprintf(output, "%d ", tag[i]);
    }

    fprintf(output, "\n\nDecrypting...\n");
    stream_init(&ctx, key, nonce);
    fprintf(output, "\nThe initial state is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    stream_proc_ad(&ctx, ad, 32);
    fprintf(output, "\nState after processing associated data is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    stream_dec(&ctx, src, dst, 32);
    fprintf(output, "\nState after decrypting source data is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    fprintf(output, "\nPlaintext is: \n");
    for (int i = 0; i < 32; i++) {
        fprintf(output, "%d ", src[i]);
    }

    stream_finalize(&ctx, tag);
    fprintf(output, "\nState after finalizing is: \n");
    for (int i = 0; i < 8; i++) {
        print_m128i(output, ctx.state[i]);
    }

    fprintf(output, "\nTag is: \n");
    for (int i = 0; i < 16; i++) {
        fprintf(output, "%d ", tag[i]);
    }

    fclose(output);
    return 0;
}