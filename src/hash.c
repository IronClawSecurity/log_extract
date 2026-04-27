#include "log_extract.h"
#include "hash.h"

/*
 * SHA-256 implementation — public domain
 * Based on the specification in FIPS 180-4
 */

typedef struct {
    unsigned int state[8];
    unsigned long long count;
    unsigned char buf[64];
} sha256_ctx;

static const unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const unsigned char *data)
{
    unsigned int a, b, c, d, e, f, g, h, t1, t2, w[64];
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)data[i*4] << 24) |
               ((unsigned int)data[i*4+1] << 16) |
               ((unsigned int)data[i*4+2] << 8) |
               ((unsigned int)data[i*4+3]);

    for (i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len)
{
    size_t i;
    unsigned int idx = (unsigned int)(ctx->count & 63);

    ctx->count += len;

    for (i = 0; i < len; i++) {
        ctx->buf[idx++] = data[i];
        if (idx == 64) {
            sha256_transform(ctx, ctx->buf);
            idx = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char hash[32])
{
    unsigned int idx = (unsigned int)(ctx->count & 63);
    unsigned long long bits = ctx->count * 8;
    int i;

    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buf[idx++] = 0;
        sha256_transform(ctx, ctx->buf);
        idx = 0;
    }
    while (idx < 56) ctx->buf[idx++] = 0;

    for (i = 7; i >= 0; i--)
        ctx->buf[idx++] = (unsigned char)(bits >> (i * 8));

    sha256_transform(ctx, ctx->buf);

    for (i = 0; i < 8; i++) {
        hash[i*4]   = (unsigned char)(ctx->state[i] >> 24);
        hash[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        hash[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        hash[i*4+3] = (unsigned char)(ctx->state[i]);
    }
}

int hash_sha256_file(const char *path, char *hex_out, size_t bufsz)
{
    FILE *f;
    sha256_ctx ctx;
    unsigned char buf[65536];
    unsigned char hash[32];
    size_t n;
    int i;

    if (bufsz < 65) return -1;

    f = fopen(path, "rb");
    if (!f) {
        log_error("hash: cannot open %s", path);
        return -1;
    }

    sha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);
    fclose(f);

    sha256_final(&ctx, hash);

    for (i = 0; i < 32; i++)
        snprintf(hex_out + i * 2, 3, "%02x", hash[i]);
    hex_out[64] = '\0';

    return 0;
}

int hash_write_sidecar(const char *archive_path, const char *hex)
{
    char sidecar[MAX_PATH_LEN];
    FILE *f;
    const char *basename;

    snprintf(sidecar, sizeof(sidecar), "%s.sha256", archive_path);

    f = fopen(sidecar, "w");
    if (!f) {
        log_error("hash: cannot write sidecar %s", sidecar);
        return -1;
    }

    basename = strrchr(archive_path, PATH_SEP);
    basename = basename ? basename + 1 : archive_path;

    fprintf(f, "%s  %s\n", hex, basename);
    fclose(f);

    log_verbose("hash: wrote %s", sidecar);
    return 0;
}
