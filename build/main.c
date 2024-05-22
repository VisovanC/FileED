#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/wait.h>

#define KEY_SIZE 16
unsigned char key[KEY_SIZE];
unsigned char iv[KEY_SIZE];

void errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void KeyGen() {
    if (!RAND_bytes(key, sizeof(key)))
        errors("Generating key failed");
    if (!RAND_bytes(iv, sizeof(iv)))
        errors("Generating IV failed");
}

void Encryption(const char *InFile, const char *OutFile) {
    FILE *in = fopen(InFile, "rb");
    if (!in) errors("Opening input file failed");

    FILE *out = fopen(OutFile, "wb");
    if (!out) errors("Opening output file failed");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) errors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        errors("EVP_EncryptInit_ex failed");

    unsigned char inBuf[1024];
    unsigned char outBuf[1024 + EVP_CIPHER_block_size(EVP_aes_128_cfb())];
    int EBytesRead, outLen;

    fwrite(iv, 1, sizeof(iv), out);

    while ((EBytesRead = fread(inBuf, 1, sizeof(inBuf), in)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, EBytesRead))
            errors("EVP_EncryptUpdate failed");
        fwrite(outBuf, 1, outLen, out);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outBuf, &outLen))
        errors("EVP_EncryptFinal_ex failed");
    fwrite(outBuf, 1, outLen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void Decryption(const char *InFile, const char *OutFile) {
    FILE *in = fopen(InFile, "rb");
    if (!in) errors("Opening input file failed");

    FILE *out = fopen(OutFile, "wb");
    if (!out) errors("Opening output file failed");

    if (fread(iv, 1, sizeof(iv), in) != sizeof(iv)) errors("Reading IV failed");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) errors("EVP_CIPHER_CTX_new failed");


    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        errors("EVP_DecryptInit_ex failed");

    unsigned char inBuf[1024];
    unsigned char outBuf[1024 + EVP_CIPHER_block_size(EVP_aes_128_cfb())];
    int DBytesRead, outLen;

    while ((DBytesRead = fread(inBuf, 1, sizeof(inBuf), in)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, DBytesRead))
            errors("EVP_DecryptUpdate failed");
        fwrite(outBuf, 1, outLen, out);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, outBuf, &outLen))
        errors("EVP_DecryptFinal_ex failed");
    fwrite(outBuf, 1, outLen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt/decrypt> <inputfile> <outputfile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    KeyGen();

    pid_t p = fork();
    if (p < 0) {
        errors("Fork failed");
    } else if (p == 0) {
        if (strcmp(argv[1], "encrypt") == 0) {
            Encryption(argv[2], argv[3]);
        } else if (strcmp(argv[1], "decrypt") == 0) {
            Decryption(argv[2], argv[3]);
        } else {
            fprintf(stderr, "Unknown operation: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    } else {
        wait(NULL);
    }

    return EXIT_SUCCESS;
}
