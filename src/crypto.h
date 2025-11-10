#ifndef CRYPTO__H_INCLUDE
#define CRYPTO__H_INCLUDE

#include "basic.h"
#include "x509.h"

// A struct containing a generic public key. Use extract_self_sign_for_code_sign to create one.
//
// exp_sig_size is read-only and contains the fixed size in bytes of a signature from this type of
// public key. alg_idx is read-only and contains an internal identifier that is unique to both the
// specific public key algorithm used by this public key *and* the cryptography provider which
// implements the algorithm. All other fields are not intended for public use.
//
// This structure is effectively a discriminated union, with alg_idx acting as the discriminant.
// It is designed specifically to support backwards-compatible extension with new public key
// algorithms and crypto providers. OpenSSL can be replaced in whole or in part, down to individual
// algorithms. In production I would expect this to eventually be necessary, as OpenSSL has numerous
// incompatible versions, is slow to add new algorithms, has had numerous CVEs, and has a
// heinous legacy API.
typedef struct PubKey {
  uinta exp_sig_size;
  uint32 alg_idx;
  union {
    struct {
      void *pkey;
      void *md_ctx;
      const void *md;
    } openssl;
  };
} PubKey;

// Status code for attempting to extract a public key from a parsed x509 certificate.
// CERT_OK is the only "success" code, all others are errors.
typedef enum {
  CERT_OK,
  EXPIRED,
  INVALID_USAGE,
  INVALID_SELF_SIGN,
  INVALID_SIG,
  INVALID_PUB_KEY,
  INVALID_PUB_KEY_PARAMS,
  UNSUPPORTED_ALG,
} ExtractCode;

// This function takes a parsed x509 certificate and attempts to verify it as a self-signed
// certificate. A generic public key will be returned only if the certificate had a valid
// self-signature and no inconsistent fields or extensions.
//
// raw_cert must point to the begining of a x509 certificate and fields must be completely filled
// out by function parse_x509. now ought to be the current unix timestamp from time(NULL).
//
// ret_pub_key will be overwritten with a new public key if this function returns CERT_OK. The
// contents of ret_pub_key are undefined and liable to change for any other return value.
// ret_pub_key is a structure that may contain RAII allocated data, and so pub_key_free must
// eventually be called on it if this function returns CERT_OK. Do not call pub_key_free on it if
// this function does not return CERT_OK.
//
// We assume that the signature algorithm used to sign the certificate is the same as the one which
// will be used to sign bash scripts. The returned public key will only be able to verify signatures
// of that type.
ExtractCode extract_self_sign_for_code_sign(const byte *raw_cert, const x509Fields *fields, time_t now,
                              PubKey *ret_pub_key);

// pub_key must be a valid public key. This public key will be used to validate the signature
// pointed to by sig and sig_size on the contents of data and data_size.
//
// This function will return true only if the signature was valid and from the given public key.
bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size);

// Deallocates the public key returned by extract_self_sign_for_code_sign.
//
// This function ought to be unnecessary, but libs like openssl forces us to allocate.
void pub_key_free(PubKey *pub_key);

#endif
