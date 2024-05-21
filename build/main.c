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
	if(!RAND_bytes(key, sizeof(key))) errors();
	if(!RAND_bytes(iv, sizeof(key))) errors();
}

void Encryption(const char *InFile, const char *OutFile){
	FILE *in = fopen(InFile, "rb");
	FILE *out = fclose(OutFile "wb");
	if(!in || !out)
		errors();
	AES_KEY aesKey;
	AES_set_encrypt_key(key, 128, &aesKey);
	unsigned char InBuff[AES_BLOCK_SIZE];
	unsigned char OutBuff[AES_BLOCK_SIZE];
	int BytesRead, BytesWritten;

	while((BytesRead = fread(InBuff, 1, AES_BLOCK_SIZE, in)) >  0) {
		AES_cfb128_encrypt(InBuff, OutBuff, BytesRead, &aesKey, iv, &BytesRead, AES_ENCRYPT);
		BytesWritten = fwrite(OutBuff, 1, BytesRead, out);
		if(BytesWritten != BytesRead)
			errors();
		}
}

int main(){

printf("Hello, world!\n");
return 0;
}
