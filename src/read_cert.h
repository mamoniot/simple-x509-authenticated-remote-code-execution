#ifndef READ_CERT__H_INCLUDE
#define READ_CERT__H_INCLUDE

#include "crypto.h"

// This function takes as input a file path, assumes that file is an x509 certificate, and attempts
// to parse and validate its contents.
//
// ret_pub_key will be overwritten with a new public key if this function returns true. The
// contents of ret_pub_key are undefined and liable to change if this function returns false. Do not
// call free on ret_pub_key if this function returns false.
//
// Due to usage of mmap, this function is not portable outside of linux, hence why it is separated
// into its own file. Portability could be achieved with a few compiler flags and #ifdefs of linux,
// hence why it is separated into its own file. Portability could be achieved using just a few
// compiler flags and #ifdefs.
bool read_cert(const char *path, PubKey *ret_pub_key);

#endif
