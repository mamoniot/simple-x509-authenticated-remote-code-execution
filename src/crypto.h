#include "basic.h"
#include "x509.h"

typedef struct PubKey PubKey;

bool pub_key_extract(byte *raw_cert, const x509Fields *fields, PubKey *ret_pub_key);

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size);

typedef struct {
  const byte *oid;
  uinta oid_size;
  bool (*parse_params)(byte*, uinta, uinta);
  // SigID sig_id;
  // HashID hash_id;
} SupportedAlg;

extern const SupportedAlg supported_algs[];
extern const uinta supported_algs_size;
