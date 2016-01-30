#include "cryptogator_algorithms.hh"
int main(int argc, char** argv){
	if (argc != 2){
		fprintf(stderr, "Usage: cryptogator inputfile \n");
		exit(1);
	}
	// AES algorithm
	//RunAES(argv[1], 128, 5);
	//RunRSA(argv[1], 1024, 10);

	RunHMAC(argv[1], GCRY_MAC_HMAC_MD5, 10);
	RunHMAC(argv[1], GCRY_MAC_HMAC_SHA1, 10);
	RunHMAC(argv[1], GCRY_MAC_HMAC_SHA256, 10);
	return 0;
}