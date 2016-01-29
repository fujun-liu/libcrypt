#include "cryptogator_algorithms.hh"

void run_AES(char* filename, int keybits, int rounds){
	


	FILE* f = fopen(filename, "rb");
	int algo = GCRY_CIPHER_AES128, mode = GCRY_CIPHER_MODE_CTR;
	if (keybits == 128) 
		algo = GCRY_CIPHER_AES128;
	else if (keybits == 256)
		algo = GCRY_CIPHER_AES256;
	else{
		fprintf(stderr, "unknown AES algorithm\n");
	}
	// result file name
	char ret_name[80];
    sprintf(ret_name, "algo:%s%d.txt",  gcry_cipher_algo_name(algo), keybits);

	int keylen = keybits/8;
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	void* plaintext = calloc(1, filesz);
	void* cipher = calloc(1, filesz);
	fread(plaintext, 1, filesz, f);
	fclose(f);

	// first we initlize gcrypto
	gcrypt_init();
	//int keylen = gcry_cipher_get_algo_keylen(algo); // key length 
	int blklen = gcry_cipher_get_algo_blklen(algo); // block length
	unsigned char* key = (unsigned char*)malloc(keylen);
	unsigned char* iv = (unsigned char*)malloc(blklen);

    float* etime = (float*)malloc(rounds*sizeof(float));
    float* dtime = (float*)malloc(rounds*sizeof(float));
    for (int r = 0; r < rounds; ++ r){
    	

		fprintf(stderr, "keylen %d, blklen: %d\n", keylen, blklen);

		// declare cipher handle
		gcry_cipher_hd_t hde; // encrption handle
		gcry_cipher_hd_t hdd; // decrption handle
		gcry_error_t err = 0;

	    clock_t t1, t_encrypt, t_decrypt;
	    int display = 30;

		// both key and iv are random numbers, so there are different in each iteration
		gcry_randomize(key, keylen, GCRY_STRONG_RANDOM);
	    gcry_randomize(iv, keylen, GCRY_STRONG_RANDOM);
	    
		// creat cipher handle
		err = gcry_cipher_open(&hde, algo, mode, 0);
		if (!err){
			err = gcry_cipher_open(&hdd, algo, mode, 0);
		}
		if (err){
			fprintf(stderr, "gcry_cipher_open failed \n");
			exit(1);
		}
		// set key
	    err = gcry_cipher_setkey(hde, (const void *)key, keylen);
	    if (!err){
	    	err = gcry_cipher_setkey(hdd, (const void *)key, keylen);
	    }
	    if (err){
	    	fprintf(stderr, "gcry_cipher_setkey failed \n");
			exit(1);
	    }
		// set ctr
		err = gcry_cipher_setctr(hde, (const void *)iv, blklen);
		if (!err){
			err = gcry_cipher_setctr(hdd, (const void *)iv, blklen);
		}
		if (err){
	    	fprintf(stderr, "gcry_cipher_setctr failed \n");
			exit(1);
	    }
	    printf("plaintext(%d):", display);
		for (int i = 0; i < display; ++ i){
			printf("%c ", ((char*)plaintext)[i]);
		}
		printf("\n");

	    t1 = clock();
	    err = gcry_cipher_encrypt(hde, (unsigned char*)cipher, filesz, (unsigned char*)plaintext, filesz);
	    if (err){
	    	fprintf(stderr, "gcry_cipher_encrypt failed \n");
			exit(1);
	    }
	    t_encrypt = clock();

		printf("   cipher(%d):", display);
		for (int i = 0; i < display; ++ i){
			printf("%c ", ((char*)cipher)[i]);
		}
		printf("\n");

	    // decruption is in place
		err = gcry_cipher_decrypt(hdd, (unsigned char*)cipher, filesz, NULL, 0);
		if (err){
			fprintf(stderr, "gcry_cipher_decrypt failed \n");
			exit(1);
		}
		t_decrypt = clock();

		printf("decrption(%d):", display);
		for (int i = 0; i < display; ++ i){
			printf("%c ", ((char*)cipher)[i]);
		}
		printf("\n");

		etime[r] = (float)(t_encrypt-t1)/CLOCKS_PER_SEC;
		dtime[r] = (float)(t_decrypt - t_encrypt)/CLOCKS_PER_SEC;

		printf("****************************************************************************** \n\n");
		if(memcmp (plaintext, cipher, filesz)){
			printf("              plaintext and cipher don NOT match!\n\n");
		}else{
			printf("              %s%d Decryption is a Big Success! \n\n", gcry_cipher_algo_name(algo), keybits);
		}
		printf("***************************************************************************** \n");

		gcry_cipher_close(hde);
		gcry_cipher_close(hdd);
    }
	
    FILE* fw = fopen(ret_name, "w");
    fprintf(fw, "encrpytion time (seconds):\n");
    for (int r = 0; r < rounds; ++ r){
    	fprintf(fw, "%.4f	", etime[r]);
    }
    fprintf(fw, "\ndecrpytion time (seconds):\n");
    for (int r = 0; r < rounds; ++ r){
    	fprintf(fw, "%.4f	", dtime[r]);
    }

    fclose(fw);
	free(key);
	free(iv);
	free(plaintext);
	free(cipher);
	free(etime);
	free(dtime);
}