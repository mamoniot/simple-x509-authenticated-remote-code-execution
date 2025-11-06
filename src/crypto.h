#ifndef CRYPTO__H_INCLUDE
#define CRYPTO__H_INCLUDE

#include "openssl/evp.h"

#include "basic.h"
#include "x509.h"

typedef struct PubKey {
  uint32 alg_idx;
  union {
    struct {
      EVP_PKEY *pkey;
    } ed25519;
    struct {

    } rsa;
    struct {

    } ecdsa;
  };
} PubKey;

bool extract_self_sign(byte *raw_cert, const x509Fields *fields, time_t now, PubKey *ret_pub_key);

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size);


#endif
