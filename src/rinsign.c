/* SPDX-License-Identifier: MIT */
/* Standalone signer for the canonical RinOS v3 RIN/NDRV envelopes. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define getpid _getpid
#define fdopen _fdopen
#define close _close
#define O_BINARY _O_BINARY
#else
#include <unistd.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define RIN_MAGIC UINT32_C(0x004e4952)
#define NDRV_MAGIC UINT32_C(0x5652444e)
#define V3 UINT32_C(0x00030000)
#define HEADER_SIZE 256u
#define RDS1_MAGIC UINT32_C(0x31534452)
#define RDS1_VERSION 1u
#define RDS1_HEADER_SIZE 48u
#define RSA_PKCS1_SHA256 1u
#define SHA256_ALGORITHM 1u
#define RIN_SIGNED UINT32_C(0x40)
#define NDRV_SIGNED UINT32_C(0x1)

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read64(const uint8_t *p) {
    return (uint64_t)read32(p) | ((uint64_t)read32(p + 4) << 32);
}

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static void usage(FILE *stream) {
    fprintf(stream,
            "usage: rinsign INPUT -o OUTPUT --key PRIVATE.pem --public-key PUBLIC.der\n");
}

static int read_file(const char *path, uint8_t **out, size_t *out_size) {
    FILE *file = NULL;
    long length;
    uint8_t *data = NULL;

    file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "rinsign: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "rinsign: cannot determine size of %s\n", path);
        fclose(file);
        return -1;
    }
    if ((unsigned long long)length > SIZE_MAX) {
        fprintf(stderr, "rinsign: %s is too large\n", path);
        fclose(file);
        return -1;
    }
    data = (uint8_t *)malloc((size_t)length ? (size_t)length : 1u);
    if (!data) {
        fprintf(stderr, "rinsign: out of memory reading %s\n", path);
        fclose(file);
        return -1;
    }
    if (length && fread(data, 1, (size_t)length, file) != (size_t)length) {
        fprintf(stderr, "rinsign: cannot read %s\n", path);
        free(data);
        fclose(file);
        return -1;
    }
    fclose(file);
    *out = data;
    *out_size = (size_t)length;
    return 0;
}

static int all_zero(const uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i)
        if (p[i] != 0)
            return 0;
    return 1;
}

static int validate_unsigned(uint8_t *data, size_t size, int *is_driver) {
    uint32_t magic;
    uint32_t flags;
    size_t signature_offset;
    uint32_t signature_size;

    if (size < HEADER_SIZE) {
        fprintf(stderr, "rinsign: input is shorter than the v3 header\n");
        return -1;
    }
    magic = read32(data);
    if (magic == RIN_MAGIC) {
        if (read32(data + 4) != V3 || read16(data + 8) != HEADER_SIZE) {
            fprintf(stderr, "rinsign: input is not a canonical RIN v3 image\n");
            return -1;
        }
        *is_driver = 0;
        flags = read32(data + 16);
        signature_offset = (size_t)read64(data + 100);
        signature_size = read32(data + 108);
        if ((flags & RIN_SIGNED) != 0 || signature_offset != 0 ||
            signature_size != 0 || read16(data + 112) != 0 || read16(data + 114) != 0 ||
            !all_zero(data + 116, 32)) {
            fprintf(stderr, "rinsign: input must be unsigned and have zero signature fields\n");
            return -1;
        }
    } else if (magic == NDRV_MAGIC) {
        if (read32(data + 4) != V3 || read16(data + 8) != HEADER_SIZE) {
            fprintf(stderr, "rinsign: input is not a canonical NDRV v3 image\n");
            return -1;
        }
        *is_driver = 1;
        flags = read32(data + 20);
        signature_offset = (size_t)read64(data + 128);
        signature_size = read32(data + 136);
        if ((flags & NDRV_SIGNED) != 0 || signature_offset != 0 ||
            signature_size != 0 || read16(data + 140) != 0 || read16(data + 142) != 0 ||
            !all_zero(data + 144, 32)) {
            fprintf(stderr, "rinsign: input must be unsigned and have zero signature fields\n");
            return -1;
        }
    } else {
        fprintf(stderr, "rinsign: unsupported image magic 0x%08x\n", magic);
        return -1;
    }
    return 0;
}

static int public_der_from_private(EVP_PKEY *key, uint8_t **der, int *der_size) {
    RSA *rsa = NULL;
    unsigned char *cursor;
    int size;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        fprintf(stderr, "rinsign: private key is not RSA\n");
        return -1;
    }
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa) {
        fprintf(stderr, "rinsign: cannot access RSA private key\n");
        return -1;
    }
    size = i2d_RSAPublicKey(rsa, NULL);
    if (size <= 0) {
        RSA_free(rsa);
        fprintf(stderr, "rinsign: cannot encode RSA public key\n");
        return -1;
    }
    *der = (uint8_t *)malloc((size_t)size);
    if (!*der) {
        RSA_free(rsa);
        fprintf(stderr, "rinsign: out of memory encoding public key\n");
        return -1;
    }
    cursor = *der;
    if (i2d_RSAPublicKey(rsa, &cursor) != size) {
        free(*der);
        *der = NULL;
        RSA_free(rsa);
        fprintf(stderr, "rinsign: cannot encode RSA public key\n");
        return -1;
    }
    RSA_free(rsa);
    *der_size = size;
    return 0;
}

static int sign_sha256(EVP_PKEY *key, const uint8_t *data, size_t size,
                       uint8_t **signature, size_t *signature_size) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    size_t required = 0;
    uint8_t *result = NULL;
    int ok = -1;

    if (!ctx || EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, key) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_DigestSignUpdate(ctx, data, size) <= 0 ||
        EVP_DigestSignFinal(ctx, NULL, &required) <= 0) {
        fprintf(stderr, "rinsign: RSA-SHA256 signing setup failed\n");
        goto done;
    }
    result = (uint8_t *)malloc(required ? required : 1u);
    if (!result || EVP_DigestSignFinal(ctx, result, &required) <= 0) {
        fprintf(stderr, "rinsign: RSA-SHA256 signing failed\n");
        goto done;
    }
    if (required < 256u || required > 512u) {
        fprintf(stderr, "rinsign: RSA signature size %lu is outside 2048-4096 bit range\n",
                (unsigned long)required);
        goto done;
    }
    *signature = result;
    *signature_size = required;
    result = NULL;
    ok = 0;
done:
    free(result);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int make_temp_file(const char *output, char *path, size_t path_size, FILE **file) {
    unsigned long pid = (unsigned long)getpid();
    unsigned long stamp = (unsigned long)time(NULL);
    unsigned int attempt;
    int fd;

    for (attempt = 0; attempt < 1000; ++attempt) {
        int written = snprintf(path, path_size, "%s.tmp.%lu.%lu.%u", output, pid, stamp, attempt);
        if (written < 0 || (size_t)written >= path_size)
            return -1;
#ifdef _WIN32
        fd = _open(path, _O_BINARY | _O_WRONLY | _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
#else
        fd = open(path, O_BINARY | O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
        if (fd >= 0) {
            *file = fdopen(fd, "wb");
            if (!*file) {
                close(fd);
                remove(path);
                return -1;
            }
            return 0;
        }
        if (errno != EEXIST)
            return -1;
    }
    return -1;
}

static int publish(const char *temporary, const char *output) {
#ifdef _WIN32
    if (!MoveFileExA(temporary, output, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fprintf(stderr, "rinsign: cannot publish %s\n", output);
        return -1;
    }
    return 0;
#else
    if (rename(temporary, output) != 0) {
        fprintf(stderr, "rinsign: cannot publish %s: %s\n", output, strerror(errno));
        return -1;
    }
    return 0;
#endif
}

int main(int argc, char **argv) {
    const char *input = NULL;
    const char *output = NULL;
    const char *private_path = NULL;
    const char *public_path = NULL;
    uint8_t *image = NULL, *trusted_der = NULL, *derived_der = NULL, *signature = NULL;
    size_t image_size = 0, trusted_size = 0, derived_size = 0, signature_size = 0;
    int derived_size_i = 0;
    uint8_t content_hash[SHA256_DIGEST_LENGTH];
    uint8_t key_id[SHA256_DIGEST_LENGTH];
    EVP_PKEY *private_key = NULL;
    FILE *key_file = NULL, *temporary_file = NULL;
    char temporary_path[4096];
    int is_driver = 0;
    int expected_signature_size;
    int rc = 2;
    int i;

    temporary_path[0] = '\0';

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) output = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) private_path = argv[++i];
        else if (strcmp(argv[i], "--public-key") == 0 && i + 1 < argc) public_path = argv[++i];
        else if (!input && argv[i][0] != '-') input = argv[i];
        else { usage(stderr); goto done; }
    }
    if (!input || !output || !private_path || !public_path) {
        usage(stderr);
        goto done;
    }
    if (read_file(input, &image, &image_size) != 0 ||
        read_file(public_path, &trusted_der, &trusted_size) != 0 ||
        validate_unsigned(image, image_size, &is_driver) != 0)
        goto done;

    key_file = fopen(private_path, "rb");
    if (!key_file) {
        fprintf(stderr, "rinsign: cannot open private key %s: %s\n", private_path, strerror(errno));
        goto done;
    }
    private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    key_file = NULL;
    if (!private_key) {
        fprintf(stderr, "rinsign: cannot read private key %s\n", private_path);
        goto done;
    }
    if (public_der_from_private(private_key, &derived_der, &derived_size_i) != 0)
        goto done;
    derived_size = (size_t)derived_size_i;
    if (trusted_size != derived_size || memcmp(trusted_der, derived_der, trusted_size) != 0) {
        fprintf(stderr, "rinsign: private key does not match trusted public key\n");
        goto done;
    }
    SHA256(trusted_der, trusted_size, key_id);
    if (image_size < HEADER_SIZE || image_size > SIZE_MAX - RDS1_HEADER_SIZE - 512u) {
        fprintf(stderr, "rinsign: image is too large to sign\n");
        goto done;
    }
    expected_signature_size = EVP_PKEY_get_size(private_key);
    if (expected_signature_size < 256 || expected_signature_size > 512) {
        fprintf(stderr, "rinsign: RSA key size is outside 2048-4096 bit range\n");
        goto done;
    }
    if (is_driver) {
        put32(image + 20, read32(image + 20) | NDRV_SIGNED);
        put64(image + 128, image_size);
        put32(image + 136, RDS1_HEADER_SIZE + (uint32_t)expected_signature_size);
        put16(image + 140, RSA_PKCS1_SHA256);
        put16(image + 142, SHA256_ALGORITHM);
    } else {
        put32(image + 16, read32(image + 16) | RIN_SIGNED);
        put64(image + 100, image_size);
        put32(image + 108, RDS1_HEADER_SIZE + (uint32_t)expected_signature_size);
        put16(image + 112, RSA_PKCS1_SHA256);
        put16(image + 114, SHA256_ALGORITHM);
    }
    SHA256(image + HEADER_SIZE, image_size - HEADER_SIZE, content_hash);
    memcpy(image + (is_driver ? 144 : 116), content_hash, sizeof(content_hash));
    if (sign_sha256(private_key, image, image_size, &signature, &signature_size) != 0)
        goto done;
    if ((int)signature_size != expected_signature_size)
        goto done;

    if (make_temp_file(output, temporary_path, sizeof(temporary_path), &temporary_file) != 0) {
        fprintf(stderr, "rinsign: cannot create temporary output for %s\n", output);
        goto done;
    }
    {
        uint8_t envelope[RDS1_HEADER_SIZE] = {0};
        put32(envelope, RDS1_MAGIC);
        put16(envelope + 4, RDS1_VERSION);
        put16(envelope + 6, RDS1_HEADER_SIZE);
        put16(envelope + 8, RSA_PKCS1_SHA256);
        put16(envelope + 10, (uint16_t)signature_size);
        memcpy(envelope + 12, key_id, sizeof(key_id));
        if (fwrite(image, 1, image_size, temporary_file) != image_size ||
            fwrite(envelope, 1, sizeof(envelope), temporary_file) != sizeof(envelope) ||
            fwrite(signature, 1, signature_size, temporary_file) != signature_size ||
            fflush(temporary_file) != 0 || fclose(temporary_file) != 0) {
            temporary_file = NULL;
            fprintf(stderr, "rinsign: cannot write %s\n", output);
            goto done;
        }
        temporary_file = NULL;
    }
    if (publish(temporary_path, output) != 0)
        goto done;
    temporary_path[0] = '\0';
    printf("rinsign: signed %s -> %s\n", input, output);
    rc = 0;
done:
    if (temporary_file) fclose(temporary_file);
    if (temporary_path[0]) remove(temporary_path);
    EVP_PKEY_free(private_key);
    free(image);
    free(trusted_der);
    free(derived_der);
    free(signature);
    return rc;
}
