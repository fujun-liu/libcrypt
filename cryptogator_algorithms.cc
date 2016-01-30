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
			printf("              %s%d Decryption is a Success! \n\n", gcry_cipher_algo_name(algo), keybits);
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


void run_RSA(char* filename, int keybits, int rounds){
	// maximum block size
	int blklen = ((keybits - 384) / 8) + 37; 
	// result file name
	char ret_name[80];
    sprintf(ret_name, "algo:RSA%d.txt", keybits);

	FILE* f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	unsigned char* plaintext = (unsigned char*)calloc(1, filesz);
	unsigned char* ciphertext = (unsigned char*)calloc(1, filesz);
	fread(plaintext, 1, filesz, f);
	fclose(f);
	int nblocks = filesz/blklen + (filesz%blklen != 0);
	
    float* etime = (float*)malloc(rounds*sizeof(float));
    float* dtime = (float*)malloc(rounds*sizeof(float));
    float* keytime = (float*)malloc(rounds*sizeof(float));
    // first we initlize gcrypto
	gcrypt_init();
    gcry_error_t err = 0;

    for (int r = 0; r < rounds; ++ r){
    	// generate key pairs every time
    	gcry_sexp_t rsa_parms;
	    gcry_sexp_t rsa_keypair;
	    char key_gen_cmds[40];

	    sprintf(key_gen_cmds, "(genkey (rsa (nbits 4:%d)))", keybits);
	    printf("RSA is generating key pair ...\n");
	    clock_t t_keygen1 = clock();
	    err = gcry_sexp_build(&rsa_parms, NULL, (const char*)key_gen_cmds);
	    if (err) {
	        fprintf(stderr, "gcry_sexp_build failed\n");
	        exit(1);
	    }
	    /*This function create a new public key pair using 
	    information given in the S-expression parms and stores the private 
	    and the public key in one new S-expression at the address given by r_key*/
	    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
	    keytime[r] = (float)(clock()-t_keygen1)/CLOCKS_PER_SEC;

	    if (err) {
	        fprintf(stderr, "gcry_pk_genkey failed\n");
	        exit(1);
	    }
    	gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    	gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

    	clock_t t1 = clock();
    	printf("RSA is encrypting %d blocks (ECB mode)\n", nblocks);
		for (int b = 0; b < nblocks; ++ b){
			int len = b < nblocks-1 ? blklen : filesz%blklen;
			//memcpy (block, plaintext+b*blklen, len);

			/* Create a message. */
		    gcry_mpi_t msg;
		    /*Convert the external representation of an integer stored 
		    in buffer with a length of buflen into a newly created MPI 
		    returned which will be stored at the address of r_mpi.*/
		    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char *)(plaintext+b*blklen), len, NULL);
		    if (err) {
		        fprintf(stderr, "gcry_mpi_scan failed\n");
	        	exit(1);
		    }
		    /*This function creates an internal S-expression from the string template format 
		    and stores it at the address of r_sexp*/
		    gcry_sexp_t blk_plaintext;
		    err = gcry_sexp_build(&blk_plaintext, NULL, "(data (flags raw) (value %m))", msg);
		    if (err) {
		        fprintf(stderr, "gcry_sexp_build failed\n");
	        	exit(1);
		    }

		    /* Encrypt the message. */
		    gcry_sexp_t blk_cipher;
		    err = gcry_pk_encrypt(&blk_cipher, blk_plaintext, pubk);
		    if (err) {
		        fprintf(stderr, "gcry_pk_encrypt failed\n");
	        	exit(1);
		    }

		    //This function is used to get and convert data from a list.
		    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(blk_cipher, 0, GCRYMPI_FMT_USG);
		    /*Convert the MPI a into an external representation described by format (see above) and store it 
		    in the provided buffer which has a usable length of at least the buflen bytes*/
		    err = gcry_mpi_print(GCRYMPI_FMT_USG, ciphertext+b*blklen, len, NULL, out_msg);
		    if (err){
		    	fprintf(stderr, "gcry_mpi_print failed\n");
	        	exit(1);
		    }
		}
		clock_t t2 = clock();
		// decryption ECB
		printf("RSA is decrypting %d blocks (ECB mode)\n", nblocks);
		for (int b = 0; b < nblocks; ++ b){
			int len = b < nblocks-1 ? blklen : filesz%blklen;
			//memcpy (block, plaintext+b*blklen, len);

			/* Create a message. */
		    gcry_mpi_t msg;
		    /*Convert the external representation of an integer stored 
		    in buffer with a length of buflen into a newly created MPI 
		    returned which will be stored at the address of r_mpi.*/
		    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char *)(ciphertext+b*blklen), len, NULL);
		    if (err) {
		        fprintf(stderr, "gcry_mpi_scan failed\n");
	        	exit(1);
		    }
		    /*This function creates an internal S-expression from the string template format 
		    and stores it at the address of r_sexp*/
		    gcry_sexp_t blk_cipher;
		    err = gcry_sexp_build(&blk_cipher, NULL, "(data (flags raw) (value %m))", msg);
		    if (err) {
		        fprintf(stderr, "gcry_sexp_build failed\n");
	        	exit(1);
		    }

		    /* Decrypt the message. */
		    gcry_sexp_t blk_decryption;
		    err = gcry_pk_decrypt(&blk_decryption, blk_cipher, privk);
		    if (err) {
		        fprintf(stderr, "gcry_pk_decrypt failed\n");
	        	exit(1);
		    }

		    //This function is used to get and convert data from a list.
		    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(blk_decryption, 0, GCRYMPI_FMT_USG);
		    err = gcry_mpi_print(GCRYMPI_FMT_USG, ciphertext+b*blklen, len, NULL, out_msg);
		    if (err){
		    	fprintf(stderr, "gcry_mpi_print failed\n");
	        	exit(1);
		    }
		}
		clock_t t3 = clock();

		etime[r] = (float)(t2-t1)/CLOCKS_PER_SEC;
		dtime[r] = (float)(t3 - t2)/CLOCKS_PER_SEC;

		printf("****************************************************************************** \n\n");
		if(memcmp (plaintext, ciphertext, filesz)){
			printf("              plaintext and ciphertext don NOT match!\n\n");
		}else{
			printf("              RSA%d Decryption is a Success! \n\n", keybits);
		}
		printf("***************************************************************************** \n");

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
    fprintf(fw, "\nkey generation time (seconds):\n");
    for (int r = 0; r < rounds; ++ r){
    	fprintf(fw, "%.4f	", keytime[r]);
    }
    fclose(fw);

	free(plaintext);
	free(ciphertext);
	free(etime);
	free(dtime);
	free(keytime);
}