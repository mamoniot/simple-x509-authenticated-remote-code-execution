#include "assert.h"

#include "openssl/evp.h"

#include "crypto.h"

typedef struct {
  const byte *oid;
  uinta oid_size;
  uinta exp_sig_size;
  bool (*extract_key)(byte *, const x509Fields *, PubKey *);
  bool (*verify_sig)(PubKey *, const byte *, uinta, const byte *,
                     uinta);
} SupportedAlg;

bool openssl_extract(byte *raw_cert, const x509Fields *fields, int key_type, PubKey *ret_pub_key) {
  // There must not be a params field.
  if (fields->pub_key_oid_end != fields->pub_key_id_end) {
    return false;
  }

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(key_type, NULL, &raw_cert[fields->pub_key_start],
                                               fields->pub_key_end - fields->pub_key_start);
  if (pkey == NULL) {
    return false;
  }

  ret_pub_key->openssl_ed.pkey = pkey;
  return true;
}

bool ed25519_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  return openssl_extract(raw_cert, fields, EVP_PKEY_ED25519, ret_pub_key);
}

bool ed448_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  return openssl_extract(raw_cert, fields, EVP_PKEY_ED448, ret_pub_key);
}

bool p384_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  return openssl_extract(raw_cert, fields, EVP_PKEY_EC, ret_pub_key);
}

bool ed25519_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig, uinta sig_size) {
  // TODO: Reuse this context.
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    return false;
  }

  if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub_key->openssl_ed.pkey) == 0) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  bool ret = EVP_DigestVerify(ctx, sig, sig_size, data, data_size) == 1;
  EVP_MD_CTX_free(ctx);
  return ret;
}

#define ed448_verify ed25519_verify



#define TABULATE(...) {__VA_ARGS__}
#define DECL_ALG(name, size, oid)                                                                  \
  static const byte MACRO_CAT(name, _oid)[] = oid;                                                 \
  static const SupportedAlg name = {MACRO_CAT(name, _oid), sizeof(MACRO_CAT(name, _oid)), size,    \
                                    MACRO_CAT(name, _extract), MACRO_CAT(name, _verify)};

DECL_ALG(ed25519, 64, TABULATE(0x2b, 0x65, 0x70));
DECL_ALG(ed448, 128, TABULATE(0x2b, 0x65, 0x71));

const SupportedAlg supported_algs[] = {ed25519, ed448};
const uinta supported_algs_size = sizeof(supported_algs) / sizeof(supported_algs[0]);


bool pub_key_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key) {
  uinta pub_key_size = fields->pub_key_oid_end - fields->pub_key_oid_start;
  for_each_idx(const SupportedAlg, idx, alg, supported_algs, supported_algs_size) {
    if (alg->oid_size == pub_key_size &&
        memcmp(alg->oid, &raw_cert[fields->pub_key_oid_start], pub_key_size) == 0) {

      ret_pub_key->alg_idx = idx;
      ret_pub_key->exp_sig_size = alg->exp_sig_size;
      return alg->extract_key(raw_cert, fields, ret_pub_key);
    }
  }

  return false;
}

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size) {
  assert(pub_key->alg_idx < supported_algs_size);
  const SupportedAlg* alg = &supported_algs[pub_key->alg_idx];
  if (alg->exp_sig_size != sig_size) {
    return false;
  }
  return alg->verify_sig(pub_key, data, data_size, sig, sig_size);
}

bool certcmp(byte *raw_cert, uinta start0, uinta end0, uinta start1, uinta end1) {
  uinta size = end0 - start0;
  return size == end1 - start1 && memcmp(&raw_cert[start0], &raw_cert[start1], size) == 0;
}

bool extract_self_sign(byte *raw_cert, const x509Fields *fields, time_t now, PubKey *ret_pub_key) {
  if (fields->not_before > now || fields->not_after < now || !fields->key_cert_sign) {
    return false;
  }

  if (!certcmp(raw_cert, fields->sig_id_start, fields->sig_id_end, fields->pub_key_id_start,
               fields->pub_key_id_end)) {
    return false;
  }
  bool is_skid = fields->skid_start != IDX_NONE;
  bool is_akid = fields->akid_start != IDX_NONE;
  if (is_skid != is_akid) {
    return false;
  }
  if (is_skid && is_akid &&
      !certcmp(raw_cert, fields->skid_start, fields->skid_end, fields->akid_start,
               fields->akid_end)) {
    return false;
  }

  if (!pub_key_extract(raw_cert, fields, ret_pub_key)) {
    return false;
  }

  return pub_key_verify(ret_pub_key, &raw_cert[fields->signed_data_start],
                        fields->signed_data_end - fields->signed_data_start,
                        &raw_cert[fields->sig_start], fields->sig_end - fields->sig_start);
}
