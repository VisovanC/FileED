#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/wait.h>

#define KEY_SIZE 16
unsigned char key[KEY_SIZE];
unsigned char iv[AES_BLOCK_SIZE];

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
    FILE *In = fopen (InFile, "rb");
    FILE *Out = fopen (OutFile, "wb");
    if (!In || !Out) 
    	errors("File open failed");
    	
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv);

    unsigned char InBuff[AES_BLOCK_SIZE];
    unsigned char OutBuff[AES_BLOCK_SIZE];
    int EBytesRead, EBytesWritten;

    while ((EBytesRead = fread(InBuff, 1, AES_BLOCK_SIZE, In)) > 0) {
        EVP_EncryptUpdate(ctx, OutBuff, &EBytesWritten, InBuff, EBytesRead);
        EBytesWritten = fwrite(OutBuff, 1, EBytesRead, Out);
    }
	
    EVP_EncryptFinal_ex(ctx, OutBuff, &EBytesWritten);
    fwrite(OutBuff, 1, EBytesWritten, Out);
    
    fclose(In);
    fclose(Out);
}

void Decryption(const char *InFile, const char *OutFile) {
    FILE *In = fopen(InFile, "rb");
    FILE *Out = fopen(OutFile, "wb");
    if (!In || !Out)
    	errors("File open failed");

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv);

    unsigned char InBuff[AES_BLOCK_SIZE];
    unsigned char OutBuff[AES_BLOCK_SIZE];
    int DBytesRead, DBytesWritten;

    while ((DBytesRead = fread(InBuff, 1, AES_BLOCK_SIZE, In)) > 0) {
        EVP_DecryptUpdate(ctx, OutBuff, &DBytesWritten, InBuff, DBytesRead);
        DBytesWritten = fwrite(OutBuff, 1, DBytesRead, Out);
        
    }
    
    EVP_DecryptFinal_ex(ctx, OutBuff, &DBytesWritten);
    fwrite(OutBuff, 1, DBytesWritten, Out);

    fclose(In);
    fclose(Out);
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
