#include "crypto.h"
#include <linux/limits.h>

bool parse_empty(byte *raw_cert, uinta params_start, uinta params_end) {
  return params_start == params_end;
}

#define TABULATE(...) {__VA_ARGS__}

#define DECL_ALG(name, params, oid)                                                                \
  static const byte MACRO_CAT(name, _oid)[] = oid;                                                 \
  static const SupportedAlg name = {MACRO_CAT(name, _oid), sizeof(MACRO_CAT(name, _oid)), params};

DECL_ALG(ed25519, parse_empty, TABULATE(0x06, 0x03, 0x2b, 0x65, 0x70));

const SupportedAlg supported_algs[] = {ed25519};
const uinta supported_algs_size = sizeof(supported_algs) / sizeof(supported_algs[0]);
