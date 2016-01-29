#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <gcrypt.h>
#include <time.h>
#include "cryptogator_helper.h"

int main(int argc, char** argv){
	if (argc != 2){
		fprintf(stderr, "Usage: cryptogator inputfile \n");
		exit(1);
	}
	// first we initlize gcrypto
	gcrypt_init();

	FILE* f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);

	void* plaintext = malloc(filesz);
	void* cipher = malloc(filesz);
	fread(plaintext, 1, filesz, f);
    
	// declare cipher handle
	gcry_cipher_hd_t hd;
	gcry_error_t err = 0;
	int algo = GCRY_CIPHER_AES128, mode = GCRY_CIPHER_MODE_CTR;
	int keylen = gcry_cipher_get_algo_keylen(algo); // key length 
	int blklen = gcry_cipher_get_algo_blklen(algo); // block length
    void* key = malloc(keylen);
    void* iv = malloc(blklen);
    clock_t t1, t_encrypt, t_decrypt;
	// both key and iv are random numbers, so there are different in each iteration
	gcry_randomize((unsigned char *)key, keylen, GCRY_STRONG_RANDOM);
    gcry_randomize((unsigned char *)iv, keylen, GCRY_STRONG_RANDOM);
	// creat cipher handle
	err = gcry_cipher_open(&hd, algo, mode, 0);
	if (err){
		fprintf(stderr, "gcry_cipher_open failed \n");
		exit(1);
	}
	// set key
    err = gcry_cipher_setkey(hd, key, keylen);
    if (err){
    	fprintf(stderr, "gcry_cipher_setkey failed \n");
		exit(1);
    }
	// set ctr
	err = gcry_cipher_setctr(hd, iv, blklen);
	if (err){
    	fprintf(stderr, "gcry_cipher_setctr failed \n");
		exit(1);
    }
    t1 = clock();
    err = gcry_cipher_encrypt(hd, cipher, filesz, plaintext, filesz);
    if (err){
    	fprintf(stderr, "gcry_cipher_encrypt failed \n");
		exit(1);
    }
    t_encrypt = clock();
    // decruption is in place
	err = gcry_cipher_decrypt(hd, cipher, filesz, NULL, 0);
	if (err){
		fprintf(stderr, "gcry_cipher_decrypt failed \n");
		exit(1);
	}
	t_decrypt = clock();
	printf("It took %f seconds to entrypy and %f seconds to decrypt a file in %f MB \n", 
				(float)(t_encrypt-t1)/CLOCKS_PER_SEC, (float)(t_decrypt - t_encrypt)/CLOCKS_PER_SEC, (float)filesz/(1024*1024));
	
	printf("Now I am comparing plaintext and decryption ... \n");
	if(memcmp (plaintext, cipher, filesz)){
		printf("plaintext and cipher don NOT match.\n");
	}else{
		printf("Decryption is a Success! \n");
	}

	free(key);
	free(iv);
	free(plaintext);
	free(cipher);
	return 0;
}