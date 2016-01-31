#include "cryptogator_algorithms.hh"

void gcrypt_init()
{
	// version check
    if (!gcry_check_version (GCRYPT_VERSION)){
        fprintf(stderr, "gcry_check_version: gcrypt library version mismatch");
        return;
    }
    gcry_error_t err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN) // supress warnings
    		| gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0) // Allocate a pool of 16k secure memory.
    		| gcry_control (GCRYCTL_RESUME_SECMEM_WARN) // resume warnings
    		| gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0); // done initialization
    if (err) {
    	fprintf(stderr, "gcrypt initialization failed \n");
    }
}

void RunAES(char* filename, int keybits, int rounds){
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


void RunRSA(char* filename, int keybits, int rounds){
	// maximum block size
	//int blklen = ((keybits - 384) / 8) + 37;
	int blklen = 128; 

	FILE* f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	unsigned char* plaintext = (unsigned char*)calloc(1, filesz);
	fread(plaintext, 1, filesz, f);
	fclose(f);

	int nblocks = filesz/blklen + (filesz%blklen != 0);
	// break up whole text into blocks
	gcry_mpi_t** plaintext_msg = (gcry_mpi_t**) malloc(nblocks*sizeof(gcry_mpi_t*));
	gcry_sexp_t** cipher_msg = (gcry_sexp_t**) malloc(nblocks*sizeof(gcry_sexp_t*));
	gcry_error_t err = 0;
	for (int b = 0; b < nblocks; ++ b){
		cipher_msg[b] = (gcry_sexp_t*)malloc(sizeof(gcry_sexp_t));
		plaintext_msg[b] = (gcry_mpi_t*)malloc(sizeof(gcry_mpi_t));

		int len = b < nblocks-1 ? blklen : filesz%blklen;
		err = gcry_mpi_scan(plaintext_msg[b], GCRYMPI_FMT_USG, (const unsigned char *)(plaintext+b*blklen), len, NULL);
		if (err) {
		    fprintf(stderr, "gcry_mpi_scan failed\n");
	    	exit(1);
		}
	}

    float* etime = (float*)malloc(rounds*sizeof(float));
    float* dtime = (float*)malloc(rounds*sizeof(float));
    
    gcry_sexp_t  pubk, privk;
	gcry_sexp_t rsa_keypair;
    rsa_keypair = GenerateRSAKeyPairs(keybits);
	pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
	privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
	/*err = gcry_sexp_sscan (&pubk, NULL, sample_public_key, strlen (sample_public_key))
			| gcry_sexp_sscan (&privk, NULL, sample_private_key, strlen (sample_private_key));
	if (err){
		fprintf(stderr, "converting public/private key failed\n");
		exit(1);
	}*/

    for (int r = 0; r < rounds; ++ r){
    	// generate key pairs every time
	 	/*gcry_sexp_t rsa_keypair = GenerateRSAKeyPairs(keybits);
	 	gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
	 	gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);*/

		etime[r] = .0;
		dtime[r] = .0;
		printf("RSA%d is encrypting %d blocks (ECB mode)\n", keybits, nblocks);
		clock_t t_start = clock();
		for (int b = 0; b < nblocks; ++ b){
		    /*This function creates an internal S-expression from the string template format 
		    and stores it at the address of r_sexp*/
		    gcry_sexp_t blk_plaintext;
		    err = gcry_sexp_build(&blk_plaintext, NULL, "(data (flags raw) (value %m))", *(plaintext_msg[b]));
		    if (err) {
		        fprintf(stderr, "gcry_sexp_build failed\n");
	        	exit(1);
		    }

		    err = gcry_pk_encrypt(cipher_msg[b], blk_plaintext, pubk);
		    if (err) {
		        fprintf(stderr, "gcry_pk_encrypt failed\n");
	        	exit(1);
		    }
		    gcry_sexp_release(blk_plaintext);
		}
		etime[r] = (float)(clock() - t_start)/CLOCKS_PER_SEC;

		t_start = clock();
		printf("RSA%d is decrypting %d blocks (ECB mode)\n", keybits, nblocks);
		for (int b = 0; b < nblocks; ++ b){
		       /* Decrypt the message. */
		    gcry_sexp_t blk_decryption;
		    err = gcry_pk_decrypt(&blk_decryption, *(cipher_msg[b]), privk);
		    if (err) {
		        fprintf(stderr, "gcry_pk_decrypt failed (b:%d)\n", b);
	        	exit(1);
		    }
		    //This function is used to get and convert data from a list.
		    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(blk_decryption, 0, GCRYMPI_FMT_USG);

		    if (gcry_mpi_cmp(*(plaintext_msg[b]), out_msg)) {
			    fprintf(stderr, "gcry_mpi_cmp failed\n");
	        	exit(1);
			}
		    gcry_mpi_release(out_msg);
		    gcry_sexp_release(blk_decryption);
		}
		dtime[r] = (float)(clock() - t_start)/CLOCKS_PER_SEC;
		/*gcry_sexp_release(rsa_keypair);
		gcry_sexp_release(pubk);
		gcry_sexp_release(privk);*/
    }
	
	//release resource
	gcry_sexp_release(rsa_keypair);
	gcry_sexp_release(pubk);
	gcry_sexp_release(privk);

	// result file name
	char ret_name[80];
    sprintf(ret_name, "algo:RSA%d.txt", keybits);

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

    // release msg
    for (int b = 0; b < nblocks; ++ b){
    	gcry_mpi_release(*plaintext_msg[b]);
    	gcry_sexp_release(*cipher_msg[b]);
    }
    free(plaintext_msg);
    free(cipher_msg);
	free(plaintext);

	free(etime);
	free(dtime);
}

void ComputeHMAC(int algo, char* data, long int filesz, char* key, int keylen, unsigned char* mac_val, int mac_len){
    unsigned char* md_val = NULL;

    gcry_md_hd_t hd; // md handle
	gcry_error_t err = 0;
	//GCRY_MD_FLAG_HMAC turns the algorithm into a HMAC message authentication algorithm.
	err = gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC);
	if (err){
		fprintf(stderr, "gcry_md_open failed \n");
		exit(1);
	}
	// set key
	err = gcry_md_setkey(hd, (const void *)(&key), keylen);
	if (err){
	   	fprintf(stderr, "gcry_md_setkey failed \n");
		exit(1);
	}
	
	gcry_md_write(hd, (const void*)data, filesz);

	// read md out
	md_val = gcry_md_read(hd, algo);
	if (!md_val){
	    fprintf(stderr, "gcry_md_read failed \n");
		exit(1);
	}
	memcpy(mac_val, md_val, mac_len);
	// release handle resource
	gcry_md_close(hd);
}

void RunHMAC(char* filename, int algo, int rounds){

    FILE* f = fopen(filename, "rb");
    if (!f){
    	fprintf(stderr, "%s is not found!\n", filename);
    	exit(1);
    }
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* data = (char*)calloc(1, filesz);
	fread(data, 1, filesz, f);
	fclose(f);

	const int keylen = 64;
	char key[keylen];
    int mac_len = gcry_md_get_algo_dlen(algo);
    unsigned char* mac_val = (unsigned char*)malloc(mac_len);
    float* mdtime = (float*)malloc(rounds*sizeof(float));

    for (int r = 0; r < rounds; ++ r){
		// generate random key in each iteration
		gcry_randomize((unsigned char *)(&key), keylen, GCRY_STRONG_RANDOM);

	    clock_t t_start = clock();
	    ComputeHMAC(algo, data, filesz, key, keylen, mac_val, mac_len);
		mdtime[r] = (float)(clock() - t_start)/CLOCKS_PER_SEC;
		printf("****HMAC:%s**** \n", gcry_md_algo_name (algo));
		for (int i = 0; i < mac_len; ++ i) fprintf(stderr, "%c", mac_val[i]);
		printf("\n****HMAC:%s*****\n", gcry_md_algo_name (algo));
    }
	
	// result file which contains the time
	char ret_name[80];
    sprintf(ret_name, "algo:%s.txt",  gcry_md_algo_name (algo));
    FILE* fw = fopen(ret_name, "w");
    fprintf(fw, "md time (seconds):\n");
    for (int r = 0; r < rounds; ++ r){
    	fprintf(fw, "%.4f	", mdtime[r]);
    }
    fclose(fw);

    free(mac_val);
	free(data);
	free(mdtime);
}

gcry_sexp_t GenerateRSAKeyPairs(int rsa_keybits){
	//Generate digital sinature using RSA
	gcry_sexp_t rsa_parms;
	gcry_sexp_t rsa_keypair;
	char key_gen_cmds[40];

	sprintf(key_gen_cmds, "(genkey (rsa (nbits 4:%d)))", rsa_keybits);
	printf("RSA is generating key pair ...\n");
	gcry_error_t err;
	err = gcry_sexp_build(&rsa_parms, NULL, (const char*)key_gen_cmds);
	if (err) {
	    fprintf(stderr, "gcry_sexp_build failed\n");
	    exit(1);
	}
	/*This function create a new public key pair using 
	information given in the S-expression parms and stores the private 
	and the public key in one new S-expression at the address given by r_key*/
	err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
	if (err) {
	    fprintf(stderr, "gcry_pk_genkey failed\n");
	    exit(1);
	}
	return rsa_keypair;
}

void RunSignature(char* filename, int algo, int rsa_keybits){
	// read file
    FILE* f = fopen(filename, "rb");
    if (!f){
    	fprintf(stderr, "%s is not found!\n", filename);
    	exit(1);
    }
	fseek(f, 0, SEEK_END);
	long int filesz = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* data = (char*)calloc(1, filesz);
	fread(data, 1, filesz, f);
	fclose(f);
	gcry_error_t err;

	// hmac file
	// generate HMAC key
	const int keylen = 64;
	char key[keylen];
    gcry_randomize((unsigned char *)(&key), keylen, GCRY_STRONG_RANDOM);
    int mac_len = gcry_md_get_algo_dlen(algo);
    unsigned char* mac_val = (unsigned char*)malloc(mac_len);
    ComputeHMAC(algo, data, filesz, key, keylen, mac_val, mac_len);

 	//generate key pair
 	gcry_sexp_t rsa_keypair = GenerateRSAKeyPairs(rsa_keybits);
 	gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
 	gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
 	

	/*Convert the external representation of an integer stored 
	in buffer with a length of buflen into a newly created MPI 
	returned which will be stored at the address of r_mpi.*/
	gcry_mpi_t msg;
	size_t nscanned = 0;
	err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char *)mac_val, mac_len, &nscanned);
	if (err) {
	    fprintf(stderr, "gcry_mpi_scan failed\n");
	   	exit(1);
	}
	/*This function creates an internal S-expression from the string template format 
	and stores it at the address of r_sexp*/
	gcry_sexp_t plaintext;
	err = gcry_sexp_build(&plaintext, NULL, "(data (flags raw) (value %m))", msg);
	if (err) {
	    fprintf(stderr, "gcry_sexp_build failed\n");
	   	exit(1);
	}

	/* Encrypt the message. */
	gcry_sexp_t sign;
	err = gcry_pk_sign(&sign, plaintext, privk);
	if (err) {
	    fprintf(stderr, "gcry_pk_sign failed\n");
	   	exit(1);
	}
    // verify signature
	err = gcry_pk_verify(sign, plaintext, pubk);
	if (err){
		fprintf(stderr, "signature and plaintext don't match\n");
	}

	gcry_mpi_t out_msg = gcry_sexp_nth_mpi(sign, 0, GCRYMPI_FMT_USG);
	fprintf(stderr, "The RSA%d signature of file %s is:\n", rsa_keybits, filename);
	gcry_mpi_dump(out_msg);
	fprintf(stderr, "\n");

	gcry_mpi_release(msg);
	gcry_mpi_release(out_msg);
	gcry_sexp_release(plaintext);
	gcry_sexp_release(sign);
	//release resource
	gcry_sexp_release(rsa_keypair);
	gcry_sexp_release(pubk);
	gcry_sexp_release(privk);

    free(mac_val);
	free(data);
}