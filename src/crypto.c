#include "assert.h"

#include "basic.h"
#include "openssl/evp.h"
#include "openssl/param_build.h"
#include "string.h"

#include "x509.h"
#include "crypto.h"

typedef struct {
  const byte *oid;
  uinta oid_size;
  ExtractCode (*extract_key)(byte *, const x509Fields *, PubKey *);
  bool (*verify_sig)(PubKey *, const byte *, uinta, const byte *, uinta);
  void (*free)(PubKey *);
} SupportedAlg;

bool certeq(byte *raw_cert, uinta start0, uinta end0, uinta start1, uinta end1) {
  return memeq(&raw_cert[start0], end0 - start0, &raw_cert[start1], end1 - start1);
}

ExtractCode ed_extract(byte *raw_cert, const x509Fields *fields, int key_type,
                       PubKey *ret_pub_key) {
  // There must not be a params field.
  if (fields->pub_key_oid_end != fields->pub_key_id_end) {
    return INVALID_PUB_KEY_PARAMS;
  }

  // The signature and public key ids must match with ed25519 and ed448.
  if (!certeq(raw_cert, fields->sig_id_start, fields->sig_id_end, fields->pub_key_id_start,
               fields->pub_key_id_end)) {
    return INVALID_SIG;
  }

  // Construct the key using OpenSSL.
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(key_type, NULL, &raw_cert[fields->pub_key_start],
                                               fields->pub_key_end - fields->pub_key_start);
  if (pkey == NULL) {
    return INVALID_PUB_KEY;
  }

  ret_pub_key->openssl.pkey = pkey;
  ret_pub_key->openssl.md = NULL;
  return CERT_OK;
}

ExtractCode ed25519_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  ret_pub_key->exp_sig_size = 64;
  return ed_extract(raw_cert, fields, EVP_PKEY_ED25519, ret_pub_key);
}
ExtractCode ed448_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  ret_pub_key->exp_sig_size = 114;
  return ed_extract(raw_cert, fields, EVP_PKEY_ED448, ret_pub_key);
}

ExtractCode rsa_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  const byte RSA_SHA256_OID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
  const byte RSA_SHA384_OID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};
  const byte RSA_SHA512_OID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};
  // NOTE: This function can only support self-signed certificates, a refactor would be necessary
  // to support certificate chains, which was the case anyways.

  // Make sure public key params is null.
  uinta idx = fields->pub_key_oid_end;
  parse_null(raw_cert, &idx, fields->pub_key_id_end);
  if (idx != fields->pub_key_id_end) {
    return INVALID_PUB_KEY_PARAMS;
  }

  // Get sha size.
  byte *sig_oid = &raw_cert[fields->sig_oid_start];
  uinta sig_oid_size = fields->sig_oid_end - fields->sig_oid_start;

  if (memeq(sig_oid, sig_oid_size, RSA_SHA256_OID, sizeof(RSA_SHA256_OID))) {
    ret_pub_key->openssl.md = EVP_sha256();
  } else if (memeq(sig_oid, sig_oid_size, RSA_SHA384_OID, sizeof(RSA_SHA384_OID))) {
    ret_pub_key->openssl.md = EVP_sha384();
  } else if (memeq(sig_oid, sig_oid_size, RSA_SHA512_OID, sizeof(RSA_SHA512_OID))) {
    ret_pub_key->openssl.md = EVP_sha512();
  } else {
    return UNSUPPORTED_ALG;
  }

  // Parse public key fields.
  // We do not provide detailed errors when parsing a public key. This is generally considered bad
  // practice, since such errors are sometimes used as components of exploit chains.
  idx = fields->pub_key_start;
  uinta seq_end = 0;
  if (parse_data_element(raw_cert, DER_SEQUENCE, &idx, fields->pub_key_end, &seq_end) != OK) {
    return INVALID_PUB_KEY;
  }

  uinta modulus_end = 0;
  if (parse_data_element(raw_cert, DER_INTEGER, &idx, seq_end, &modulus_end) != OK) {
    return INVALID_PUB_KEY;
  }

  uinta modulus_start = idx;
  idx = modulus_end;

  uinta exp_end = 0;
  if (parse_data_element(raw_cert, DER_INTEGER, &idx, seq_end, &exp_end) != OK) {
    return INVALID_PUB_KEY;
  }
  if (exp_end != seq_end) {
    return INVALID_PUB_KEY;
  }

  uinta exp_start = idx;

  // Determine if this is rsa3072 or rsa4096, reject all others since their key sizes are too small.
  switch (modulus_end - modulus_start) {
  case 385:
    ret_pub_key->exp_sig_size = 384;
    break;
  case 513:
    ret_pub_key->exp_sig_size = 512;
    break;
  default:
    return UNSUPPORTED_ALG;
  }

  // Construct the key using OpenSSL.
  ExtractCode ret = INVALID_PUB_KEY;
  BIGNUM *modulus = NULL;
  BIGNUM *exp = NULL;
  OSSL_PARAM_BLD *rsa_build = NULL;
  OSSL_PARAM *rsa_params = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  // This call may fail if the integer cannot be decoded.
  modulus = BN_bin2bn(&raw_cert[modulus_start], modulus_end - modulus_start, NULL);
  if (modulus == NULL) {
    goto out;
  }
  // This call may fail if the integer cannot be decoded.
  exp = BN_bin2bn(&raw_cert[exp_start], exp_end - exp_start, NULL);
  if (exp == NULL) {
    goto out;
  }

  // This call should not fail.
  rsa_build = OSSL_PARAM_BLD_new();
  if (rsa_build == NULL) {
    goto out;
  }

  // These calls may fail if the integers are negative.
  if (OSSL_PARAM_BLD_push_BN(rsa_build, "n", modulus) != 1 ||
      OSSL_PARAM_BLD_push_BN(rsa_build, "e", exp) != 1 ||
      OSSL_PARAM_BLD_push_BN(rsa_build, "d", NULL) != 1) {
    goto out;
  }

  // This call should not fail.
  rsa_params = OSSL_PARAM_BLD_to_param(rsa_build);
  if (rsa_params == NULL) {
    goto out;
  }

  // This call should not fail.
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (ctx == NULL) {
    goto out;
  }

  // This call should not fail.
  if (EVP_PKEY_fromdata_init(ctx) != 1) {
    goto out;
  }

  // This call should not fail.
  if (EVP_PKEY_fromdata(ctx, cast(EVP_PKEY **, &ret_pub_key->openssl.pkey), EVP_PKEY_PUBLIC_KEY,
                        rsa_params) != 1) {
    if (ret_pub_key->openssl.pkey != NULL) {
      // I don't think this can happen but the OpenSSL docs do not make it clear.
      // Better safe than sorry.
      EVP_PKEY_free(ret_pub_key->openssl.pkey);
    }
    goto out;
  }
  assert(ret_pub_key->openssl.pkey != NULL);

  ret = CERT_OK;

out:
  // OpenSSL objects have weird ownership rules, so should be freed at the same time.
  if (ctx != NULL)
    EVP_PKEY_CTX_free(ctx);
  if (rsa_params != NULL)
    OSSL_PARAM_free(rsa_params);
  if (rsa_build != NULL)
    OSSL_PARAM_BLD_free(rsa_build);
  if (exp != NULL)
    BN_free(exp);
  if(modulus != NULL)
    BN_free(modulus);
  return ret;
}

bool openssl_verify(PubKey *pub_key, const byte *data, uinta data_size,
               const byte *sig, uinta sig_size) {
  if (sig_size != pub_key->exp_sig_size) {
    return false;
  }
  // TODO: Reuse this context.
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return false;
  }

  if (EVP_DigestVerifyInit(ctx, NULL, pub_key->openssl.md, NULL, pub_key->openssl.pkey) == 0) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  bool ret = EVP_DigestVerify(ctx, sig, sig_size, data, data_size) == 1;
  EVP_MD_CTX_free(ctx);
  return ret;
}
#define ed25519_verify openssl_verify
#define ed448_verify openssl_verify
#define rsa_verify openssl_verify

void openssl_free(PubKey *pub_key) { EVP_PKEY_free(pub_key->openssl.pkey); }
#define ed448_free openssl_free
#define ed25519_free openssl_free
#define rsa_free openssl_free

#define TABULATE(...) {__VA_ARGS__}
#define DECL_ALG(name, oid)                                                                        \
  static const byte MACRO_CAT(name, _oid)[] = oid;                                                 \
  static const SupportedAlg name = {MACRO_CAT(name, _oid), sizeof(MACRO_CAT(name, _oid)),          \
                                    MACRO_CAT(name, _extract), MACRO_CAT(name, _verify),           \
                                    MACRO_CAT(name, _free)};

DECL_ALG(ed25519, TABULATE(0x2b, 0x65, 0x70));
DECL_ALG(ed448, TABULATE(0x2b, 0x65, 0x71));
DECL_ALG(rsa, TABULATE(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01));

const SupportedAlg supported_algs[] = {ed25519, ed448, rsa};
const uinta supported_algs_size = sizeof(supported_algs) / sizeof(supported_algs[0]);

ExtractCode pub_key_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  for_each_idx(const SupportedAlg, idx, alg, supported_algs, supported_algs_size) {
    if (memeq(alg->oid, alg->oid_size, &raw_cert[fields->pub_key_oid_start],
              fields->pub_key_oid_end - fields->pub_key_oid_start)) {

      ret_pub_key->alg_idx = idx;
      return alg->extract_key(raw_cert, fields, ret_pub_key);
    }
  }

  return UNSUPPORTED_ALG;
}

ExtractCode extract_self_sign_for_code_sign(byte *raw_cert, const x509Fields *fields, time_t now,
                              PubKey *ret_pub_key) {
  if (fields->not_before > now || fields->not_after < now) {
    return EXPIRED;
  }
  if (!fields->key_cert_sign) {
    return INVALID_USAGE;
  }

  // We allow skid and akid to be empty since they are irrelevant for self-signed certificates.
  bool is_skid = fields->skid_start != IDX_NONE;
  bool is_akid = fields->akid_start != IDX_NONE;
  if (is_skid != is_akid) {
    return INVALID_SELF_SIGN;
  }
  if (is_skid && is_akid &&
      !certeq(raw_cert, fields->skid_start, fields->skid_end, fields->akid_start,
               fields->akid_end)) {
    return INVALID_SELF_SIGN;
  }
  // TODO: Consider comparing issuer and subject names.

  // We are going to require both key usage and extended key usage extensions.
  uint32 mask = KEY_USAGE_FLAG_SIGN | KEY_USAGE_FLAG_KEY_CERT_SIGN | KEY_USAGE_FLAG_CODE_SIGNING;
  if (!fields->has_key_usage || !fields->has_ext_key_usage || (fields->key_usage_flags & mask) != mask) {
    return INVALID_USAGE;
  }

  ExtractCode code = pub_key_extract(raw_cert, fields, ret_pub_key);
  if (code != CERT_OK) {
    return code;
  }

  if (pub_key_verify(ret_pub_key, &raw_cert[fields->signed_data_start],
                        fields->signed_data_end - fields->signed_data_start,
                        &raw_cert[fields->sig_start], fields->sig_end - fields->sig_start)) {
    return CERT_OK;
  } else {
    pub_key_free(ret_pub_key);
    return INVALID_SIG;
  }
}

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size) {
  if (pub_key->exp_sig_size != sig_size) {
    return false;
  }
  assert(pub_key->alg_idx < supported_algs_size);
  return supported_algs[pub_key->alg_idx].verify_sig(pub_key, data, data_size, sig, sig_size);
}

void pub_key_free(PubKey *pub_key) {
  assert(pub_key->alg_idx < supported_algs_size);
  return supported_algs[pub_key->alg_idx].free(pub_key);
}
