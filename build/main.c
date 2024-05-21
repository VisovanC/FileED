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



int main(){

printf("Hello, world!\n");
return 0;
}
