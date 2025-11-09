#ifndef X509__H_INCLUDE
#define X509__H_INCLUDE

#include "basic.h"

#define IDX_NONE 0
#define MAX_EXTN 64

#define DER_CONSTRUCTED 0b00100000
#define DER_BOOLEAN 1
#define DER_INTEGER 2
#define DER_BITSTRING 3
#define DER_OCTET_STRING 4
#define DER_OID 6
#define DER_SEQUENCE (DER_CONSTRUCTED | 16)
#define DER_SET (DER_CONSTRUCTED | 17)
#define DER_UTCTIME 23
#define DER_GENERALIZEDTIME 24

#define DER_EXPLICIT_0 0b10100000
#define DER_IMPLICIT_0 0b10000000
#define DER_IMPLICIT_1 0b10000001
#define DER_IMPLICIT_2 0b10000010
#define DER_EXPLICIT_3 0b10100011

#define DER_LENGTH_FORM_MASK 0b10000000
#define DER_LENGTH_INDEFINITE 0b10000000
#define DER_LENGTH_RESERVED 0b11111111

#define X509_ACCEPTED_VERSION 2

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
  INVALID_LENGTH_FORM,
  TRAILING_DATA,
  INVALID_VERSION,
  INVALID_BOOLEAN,
  INVALID_VALIDITY_TIME,
  MISMATCHED_SIG_ID,
  EXCEEDS_MAX_EXTNS,
  DUPLICATE_EXTNS,
  UNRECOGNIZED_CRITICAL_EXTN,
  INVALID_CRITICALITY,
} StatusCode;

StatusCode parse_x509(byte *raw_cert, uinta raw_cert_size, x509Fields *ret_fields);

StatusCode parse_data_element(byte *raw_cert, uint8 expected_identifier, uinta *idx,
                              uinta parent_end, uinta *ret_content_end);
StatusCode parse_null(byte *raw_cert, uinta *idx, uinta parent_end);
StatusCode parse_bitstring_no_unused(byte *raw_cert, uinta *idx, uinta parent_end,
                                     uinta *ret_content_end);

#endif
