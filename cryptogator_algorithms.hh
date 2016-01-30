#pragma once
#include <time.h>
#include "cryptogator_helper.hh"

void run_AES(char* filename, int keybits, int rounds);

void run_RSA(char* filename, int keybits, int rounds);