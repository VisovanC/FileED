#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/wait.h>

#define KEY_SIZE 16
#define IV_SIZE 16

unsigned char key[KEY_SIZE];
unsigned char iv[IV_SIZE];

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

void SaveKeyGen(const char *keyFile) {
    FILE *kf = fopen(keyFile, "wb");
    if (!kf)
        errors("Opening key file for writing failed");

    fwrite(key, 1, sizeof(key), kf);
    fwrite(iv, 1, sizeof(iv), kf);
    fclose(kf);
}

void LoadKeyGen(const char *keyFile) {
    FILE *kf = fopen(keyFile, "rb");
    if (!kf)
        errors("Opening key file for reading failed");

    fread(key, 1, sizeof(key), kf);
    fread(iv, 1, sizeof(iv), kf);
    fclose(kf);
}

void Encryption(const char *InFile, const char *OutFile, const char *keyFile) {
    KeyGen();
    SaveKeyGen(keyFile);

    FILE *in = fopen(InFile, "rb");
    FILE *out = fopen(OutFile, "wb");
    if (!in || !out)
        errors("File open failed");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) errors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        errors("EVP_EncryptInit_ex failed");

    unsigned char inBuf[1024];
    unsigned char outBuf[1024 + EVP_CIPHER_block_size(EVP_aes_128_cfb())];
    int bytesRead, outLen;

    while ((bytesRead = fread(inBuf, 1, sizeof(inBuf), in)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead))
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

void Decryption(const char *InFile, const char *OutFile, const char *keyFile) {
    LoadKeyGen(keyFile);

    FILE *in = fopen(InFile, "rb");
    FILE *out = fopen(OutFile, "wb");
    if (!in || !out)
        errors("File open failed");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) errors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        errors("EVP_DecryptInit_ex failed");

    unsigned char inBuf[1024];
    unsigned char outBuf[1024 + EVP_CIPHER_block_size(EVP_aes_128_cfb())];
    int bytesRead, outLen;

    while ((bytesRead = fread(inBuf, 1, sizeof(inBuf), in)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead))
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
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <encrypt/decrypt> <inputfile> <outputfile> <keyfile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    pid_t p = fork();
    if (p < 0) {
        errors("Fork failed");
    } else if (p == 0) {
        if (strcmp(argv[1], "encrypt") == 0) {
            Encryption(argv[2], argv[3], argv[4]);
        } else if (strcmp(argv[1], "decrypt") == 0) {
            Decryption(argv[2], argv[3], argv[4]);
        } else {
            fprintf(stderr, "Unknown operation: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    } else {
        wait(NULL);
    }

    return EXIT_SUCCESS;
}
