#include "cryptogator_algorithms.hh"
int main(int argc, char** argv){
	if (argc != 2){
		fprintf(stderr, "Usage: cryptogator inputfile \n");
		exit(1);
	}

	gcrypt_init();
	// AES128, 100 rounds
	//RunAES(argv[1], 128, 100);
	// AES256, 100 rounds
	//RunAES(argv[1], 256, 100);
	//RSA1024, 100 rounds
	RunRSA(argv[1], 1024, 100);
	//RSA4096, 100 rounds
	RunRSA(argv[1], 4096, 100);
	// MAC MD5, 100 rounds
	RunHMAC(argv[1], GCRY_MD_MD5, 100);
	// MAC SHA1, 100 rounds
	RunHMAC(argv[1], GCRY_MD_SHA1, 100);
	// MAC SHA256, 100 rounds
	RunHMAC(argv[1], GCRY_MD_SHA256, 100);
	// HMAC SHA-256 + RSA4096
	RunSignature(argv[1], GCRY_MD_SHA256, 4096);
	return 0;
}