#pragma once
#include <time.h>
#include "cryptogator_helper.hh"

void RunAES(char* filename, int keybits, int rounds);

void RunRSA(char* filename, int keybits, int rounds);
void RunRSADebug(char* filename, int keybits, int rounds);
//
void RunHMAC(char* filename, int algo, int rounds);