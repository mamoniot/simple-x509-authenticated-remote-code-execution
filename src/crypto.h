#ifndef CRYPTO__H_INCLUDE
#define CRYPTO__H_INCLUDE

#include "basic.h"
#include "x509.h"

typedef struct PubKey {
  uinta exp_sig_size;
  uint32 alg_idx;
  union {
    struct {
      void *pkey;
      const void *md;
    } openssl;
    struct {

    } ecdsa;
  };
} PubKey;

typedef enum {
  CERT_OK,
  EXPIRED,
  INVALID_CONSTRAINTS,
  INVALID_SIG,
  INVALID_PUB_KEY,
  INVALID_PUB_KEY_PARAMS,
  UNSUPPORTED_ALG,
} ExtractCode;

// We assume that the signature algorithm used to sign the certificate is the same as the one which
// will be used to sign bash scripts.
//
ExtractCode extract_self_sign(byte *raw_cert, const x509Fields *fields, time_t now,
                              PubKey *ret_pub_key);

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size);

// This function ought to be unnecessary, but openssl forces us to allocate.
void pub_key_free(PubKey *pub_key);


#endif
