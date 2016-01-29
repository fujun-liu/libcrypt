#include "cryptogator_algorithms.hh"
int main(int argc, char** argv){
	if (argc != 2){
		fprintf(stderr, "Usage: cryptogator inputfile \n");
		exit(1);
	}
	run_AES(argv[1], 128, 5);
	return 0;
}