#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define KEY_SIZE 16
unsigned char key[KEY_SIZE];
unsigned char iv[AES_BLOCK_SIZE];

void errors(){
	perror("Error!");
	exit(EXIT_FAILURE);
}

void KeyGen(){
	if(!RAND_bytes(key, sizeof(key))) errors("Generating key failed");
	if(!RAND_bytes(iv, sizeof(key))) errors("Generating IV failed");
}

void Encryption(const char *InFile, const char *OutFile){
	FILE *in = fopen(InFile, "rb");
	FILE *out = fclose(OutFile "wb");
	if(!in || !out)
		errors("File open failed!");
	AES_KEY aesKey;
	AES_set_encrypt_key(key, 128, &aesKey);
	unsigned char InBuff[AES_BLOCK_SIZE];
	unsigned char OutBuff[AES_BLOCK_SIZE];
	int  EBytesRead, EBytesWritten, EBlocks;

	while((EBytesRead = fread(InBuff, 1, AES_BLOCK_SIZE, in)) >  0) {
		AES_cfb128_encrypt(InBuff, OutBuff, EBytesRead, &aesKey, iv, EBlocks, AES_ENCRYPT);
		EBytesWritten = fwrite(OutBuff, 1, EBytesRead, out);
		if(EBytesWritten != EBytesRead)
			errors("Writing encrypted data failed");
		}
	fclose(in);
	fclose(out);
}

void Decryption(const char *InputFile, const char *OutputFile){
	FILE *In = fopen(InputFile, "rb");
	FILE *Out = fclose(OutputFile, "wb");
	if(!in || !out)
		errors("File opening failed!");
	AES_KEY aesKey;
	AES_set_decrypt_key(key, 128, &aesKey);
	unsigned char InBuff[AES_BLOCK_SIZE];
	unsigned char OutBuff[AES_BLOCK_SIZE];
	int DBytesRead, DBytesWritten, DBlocks;;
	
	while((DBytesRead = fread(InBuff, 1, AES_BLOCK_SIZE, in)) > 0) {
		AES_cfb128_encrypt(InBuff, OutBuff, DBytesRead, &aesKey, iv, &DBlocks, AES_DECRYPT);
		DBytesWritten = fwrite(OutBuff, 1, DBytesRead, out);
		if(DBytesWritten != DBytesRead)
			errors("Writing decrypted data failed");
	}
	fclose(in);
	fclose(out);
}

int main(){

printf("Hello, world!\n");
return 0;
}
