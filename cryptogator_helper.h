#ifndef CRYPTO_GATOR_HELPER_H
#define CRYPTO_GATOR_HELPER_H
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <gcrypt.h>


void gcrypt_init()
{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    const char * version = gcry_check_version(GCRYPT_VERSION);
    printf("%s vs %s \n", version, GCRYPT_VERSION);
    if (!gcry_check_version (NULL)) // GCRYPT_VERSION
    {
        fprintf(stderr, "gcrypt library version mismatch");
        return;
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
    	fprintf(stderr, "gcrypt initialization failed \n");
    }
}

#endif
