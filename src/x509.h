#ifndef X509__H_INCLUDE
#define X509__H_INCLUDE

#include "basic.h"

const uinta IDX_NONE = 0;

typedef struct {
  // Must be present.
  uinta sig_id_start;
  uinta sig_id_end;

  // Must be present.
  uinta sig_oid_start;
  uinta sig_oid_end;

  // Must be present.
  uinta sig_start;
  uinta sig_end;

  // Must be present.
  uinta pub_key_id_start;
  uinta pub_key_id_end;

  // Must be present.
  uinta pub_key_oid_start;
  uinta pub_key_oid_end;

  // Must be present.
  uinta pub_key_start;
  uinta pub_key_end;

  // Must be present.
  uinta signed_data_start;
  uinta signed_data_end;

  // Optional.
  uinta skid_start;
  uinta skid_end;

  // Optional.
  uinta akid_start;
  uinta akid_end;

  // Must be present.
  time_t not_before;
  time_t not_after;

  // Must be present.
  bool key_cert_sign;
  // uint32 path_len_constraint;
} x509Fields;

typedef enum {
  OK,
  UNEXPECTED_END_OF_DATA,
  UNEXPECTED_IDENTIFIER,
  INVALID_END_OF_DATA,
  INVALID_LENGTH_FORM,
  INVALID_LENGTH_TOO_LONG,
  TRAILING_DATA,
  INVALID_VERSION,
  INVALID_BOOLEAN,
  INVALID_VALIDITY_TIME,
  MISMATCHED_SIG_ID,
  UNKNOWN_SIG_ID,
  INVALID_SIG_PARAMS,
  EXCEEDS_MAX_EXTNS,
  DUPLICATE_EXTNS,
  UNRECOGNIZED_CRITICAL_EXTN,
  EXPLICIT_DEFAULT,
} StatusCode;

StatusCode parse_x509(byte *raw_cert, uinta raw_cert_size, x509Fields *ret_x509);

#endif
