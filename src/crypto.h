#include "basic.h"

// typedef enum {
//   SIG_NONE = 0,
//   ED25519,
//   RSA,
//   ECDSA,
// } SigID;

// typedef enum {
//   HASH_NONE = 0,
//   SHA2_256,
//   SHA2_384,
//   SHA2_512,
// } HashID;

typedef struct {
  const byte *oid;
  uinta oid_size;
  bool (*parse_params)(byte*, uinta, uinta);
  // SigID sig_id;
  // HashID hash_id;
} SupportedAlg;

extern const SupportedAlg supported_algs[];
extern const uinta supported_algs_size;
