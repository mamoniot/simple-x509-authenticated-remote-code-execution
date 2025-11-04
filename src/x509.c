#include "basic.h"
#include "crypto_layer.h"

#define DER_BOOLEAN   0b00000001
#define DER_INTEGER   0b00000010
#define DER_BITSTRING 0b00000011
#define DER_OCTET_STRING 0b00000100
#define DER_OID       0b00000110
#define DER_SEQUENCE  0b00110000
#define DER_SET       0b00110001

#define DER_LENGTH_FORM_MASK   0b10000000
#define DER_LENGTH_INDEFINITE  0b10000000
#define DER_LENGTH_RESERVED    0b11111111

#define X509_ACCEPTED_VERSION 2

typedef enum {
  SUCCESS,
  UNEXPECTED_END_OF_DATA,
  UNEXPECTED_IDENTIFIER,
  INVALID_END_OF_DATA,
  INVALID_LENGTH_FORM,
  INVALID_LENGTH_TOO_LONG,
  TRAILING_DATA,
  INVALID_VERSION,
} Code;

typedef struct {
  AlgID id;
} PublicKeyBuilder;

Code parse_data_element(byte *raw_cert, uint8 expected_identifier, inta *idx, inta parent_end,
                       inta *ret_content_end) {
  if (*idx >= parent_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (raw_cert[*idx] != expected_identifier) {
    return UNEXPECTED_IDENTIFIER;
  }

  *idx += 1;

  if (*idx >= parent_end) {
    return INVALID_END_OF_DATA;
  }

  inta length_byte = raw_cert[*idx];

  if (length_byte == DER_LENGTH_INDEFINITE ||
      length_byte == DER_LENGTH_RESERVED) {
    // Disallowed BER length type.
    return INVALID_LENGTH_FORM;
  }

  inta length = 0;
  *idx += 1;

  if ((length_byte & DER_LENGTH_FORM_MASK) > 0) {
    // Definite long form length.
    int32 length_octets = length_byte & !DER_LENGTH_FORM_MASK;
    if (*idx + length_octets > parent_end) {
      return INVALID_END_OF_DATA;
    }
    if (raw_cert[*idx] == 0) {
      // This check is not strictly necessary, but is still specified by DER.
      return INVALID_LENGTH_FORM;
    }

    for_each_lt(i, length_octets) {
      length = (length << 8) | raw_cert[*idx];
      *idx += 1;
    }

    if (length <= 127) {
      // This check is not strictly necessary, but is still specified by DER.
      return INVALID_LENGTH_FORM;
    }
  } else {
    // Definite short form length.
    length = length_byte & !DER_LENGTH_FORM_MASK;
  }

  if (*idx + length > parent_end) {
    return INVALID_LENGTH_TOO_LONG;
  }

  *ret_content_end = *idx + length;
  return SUCCESS;
}

Code parse_alg_params(byte *raw_cert, inta alg_oid_start, inta alg_oid_end, inta alg_id_end,
                      PublicKeyBuilder *public_key);

/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }*/
Code parse_alg_id(byte *raw_cert, inta *idx, inta parent_end, PublicKeyBuilder *public_key) {
  inta alg_id_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &alg_id_end);
  if (code != SUCCESS) {
    return code;
  }

  /*algorithm               OBJECT IDENTIFIER*/
  inta alg_oid_end = 0;
  code = parse_data_element(raw_cert, DER_OID, idx, alg_id_end, &alg_oid_end);
  if (code != SUCCESS) {
    return code;
  }

  inta alg_oid_start = *idx;
  *idx = alg_oid_end;

  /*parameters              ANY DEFINED BY algorithm OPTIONAL*/
  code = parse_alg_params(raw_cert, alg_oid_start, alg_oid_end, alg_id_end, public_key);
  if (code != SUCCESS) {
    return code;
  }

  *idx = alg_id_end;

  return SUCCESS;
}
/*subjectPublicKey     BIT STRING*/
Code parse_public_key(byte *raw_cert, inta *idx, inta parent_end, PublicKeyBuilder *public_key) {
  inta public_key_end = 0;
  Code code = parse_data_element(raw_cert, DER_BITSTRING, idx, parent_end, &public_key_end);
  if (code != SUCCESS) {
    return code;
  }

  // TODO: Parse public key contents.
  inta public_key_start = *idx;
  *idx = public_key_end;

  return SUCCESS;
}

/*Name ::= CHOICE { -- only one possibility for now --
   rdnSequence  RDNSequence }*/
Code parse_name(byte *raw_cert, inta *idx, inta parent_end) {
  /*RDNSequence ::= SEQUENCE OF RelativeDistinguishedName*/
  inta issuer_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &issuer_end);
  if (code != SUCCESS) {
    return code;
  }

  /*RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue*/
  inta relative_name_end = 0;
  while (relative_name_end < issuer_end) {
    code = parse_data_element(raw_cert, DER_SET, idx, issuer_end, &relative_name_end);
    if (code != SUCCESS) {
      return code;
    }
    // TODO: Should we check for sorted ordering for this set?

    /*AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }*/
    inta attribute_end = 0;
    code = parse_data_element(raw_cert, DER_SEQUENCE, idx, relative_name_end, &attribute_end);
    if (code != SUCCESS) {
      return code;
    }

    /*AttributeType ::= OBJECT IDENTIFIER*/
    inta attribute_type_end = 0;
    code = parse_data_element(raw_cert, DER_OID, idx, attribute_end, &attribute_type_end);
    if (code != SUCCESS) {
      return code;
    }

    inta attribute_type_start = *idx;
    *idx = attribute_type_end;

    /*AttributeValue ::= ANY -- DEFINED BY AttributeType*/
    inta attribute_value_end = 0;
    // TODO: Replace with choice call.
    code = parse_data_element(raw_cert, 111, idx, attribute_end, &attribute_value_end);
    if (code != SUCCESS) {
      return code;
    }
    if (attribute_end != attribute_value_end) {
      return TRAILING_DATA;
    }
    // TODO: Finish parsing contents.

    inta attribute_value_start = *idx;
    *idx = attribute_value_end;
  }

  return SUCCESS;
}
/*Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }*/
Code parse_time(byte *raw_cert, inta *idx, inta parent_end, inta *ret_unix_ts);

Code parse_optional_content(byte *raw_cert, uint8 expected_identifier, inta *idx, inta parent_end, inta *ret_content_end) {
  Code code = parse_data_element(raw_cert, expected_identifier, idx, parent_end, ret_content_end);
  switch (code) {
  case UNEXPECTED_END_OF_DATA:
  case UNEXPECTED_IDENTIFIER:
    *ret_content_end = 0;
  case SUCCESS:
    return SUCCESS;
  default:
    return code;
  }
}

Code parse_x509(byte *raw_cert, inta raw_cert_size) {
  inta idx_mem = 0;
  inta *idx = &idx_mem;

  inta cert_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, raw_cert_size, &cert_end);
  if(code != SUCCESS) {
    return code;
  }
  if (raw_cert_size != cert_end) {
    return TRAILING_DATA;
  }

  inta tbs_cert_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, cert_end, &tbs_cert_end);
  if (code != SUCCESS) {
    return code;
  }

  inta version_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &version_end);
  if (code != SUCCESS) {
    return code;
  }
  if (version_end - *idx != 1 || raw_cert[*idx] != X509_ACCEPTED_VERSION) {
    return INVALID_VERSION;
  }

  *idx = version_end;

  inta serial_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &serial_end);
  if (code != SUCCESS) {
    return code;
  }

  // Currently we do not record the serial number of the cert. There is no current plan to use it.
  *idx = serial_end;

  PublicKeyBuilder public_key = {0};
  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &public_key);
  if (code != SUCCESS) {
    return code;
  }

  /*issuer               Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != SUCCESS) {
    return code;
  }

  /*validity             Validity*/
  /*Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }*/
  inta validity_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &validity_end);
  if (code != SUCCESS) {
    return code;
  }

  /*notBefore      Time*/
  int64 not_before_ts = 0;
  code = parse_time(raw_cert, idx, validity_end, &not_before_ts);
  if (code != SUCCESS) {
    return code;
  }

  /*notAfter       Time*/
  int64 not_after_ts = 0;
  code = parse_time(raw_cert, idx, validity_end, &not_after_ts);
  if (code != SUCCESS) {
    return code;
  }
  if (validity_end != *idx) {
    return TRAILING_DATA;
  }

  /*subject              Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != SUCCESS) {
    return code;
  }

  /*subjectPublicKeyInfo SubjectPublicKeyInfo*/
  /*SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }*/
  inta public_key_info_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &public_key_info_end);
  if (code != SUCCESS) {
    return code;
  }

  code = parse_alg_id(raw_cert, idx, public_key_info_end, &public_key);
  if (code != SUCCESS) {
    return code;
  }

  code = parse_public_key(raw_cert, idx, public_key_info_end, &public_key);
  if (code != SUCCESS) {
    return code;
  }
  if (*idx != public_key_info_end) {
    return TRAILING_DATA;
  }

  /*issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL*/
  inta issuer_uid_end = 0;
  code = parse_optional_content(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &issuer_uid_end);
  if (code != SUCCESS) {
    return code;
  }

  inta issuer_uid_start = *idx;
  *idx = issuer_uid_end;

  /*subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL*/
  inta subject_uid_end = 0;
  code = parse_optional_content(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &subject_uid_end);
  if (code != SUCCESS) {
    return code;
  }

  inta subject_uid_start = *idx;
  *idx = subject_uid_end;

  /*extensions      [3]  EXPLICIT Extensions OPTIONAL*/
  /*Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension*/
  inta extensions_end = 0;
  code = parse_optional_content(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &extensions_end);
  if (code != SUCCESS) {
    return code;
  }

  inta extensions_start = *idx;
  *idx = extensions_end;

  while (*idx < extensions_end) {
    // TODO: Should we check for sorted ordering for this set?

    /*Extension  ::=  SEQUENCE  {
          extnID      OBJECT IDENTIFIER,
          critical    BOOLEAN DEFAULT FALSE,
          extnValue   OCTET STRING
                      -- contains the DER encoding of an ASN.1 value
                      -- corresponding to the extension type identified
                      -- by extnID
          }*/
    inta extension_end = 0;
    code = parse_data_element(raw_cert, DER_SEQUENCE, idx, extensions_end, &extension_end);
    if (code != SUCCESS) {
      return code;
    }

    /*extnID      OBJECT IDENTIFIER*/
    inta extn_oid_end = 0;
    code = parse_data_element(raw_cert, DER_OID, idx, extension_end, &extn_oid_end);
    if (code != SUCCESS) {
      return code;
    }

    inta extn_oid_start = *idx;
    *idx = extn_oid_end;

    /*critical    BOOLEAN DEFAULT FALSE*/
    inta critical_end = 0;
    // TODO: Replace with choice call.
    code = parse_optional_content(raw_cert, DER_BOOLEAN, idx, extension_end, &critical_end);
    if (code != SUCCESS) {
      return code;
    }

    inta critical_start = *idx;
    *idx = critical_end;

    /*extnValue   OCTET STRING
                      -- contains the DER encoding of an ASN.1 value
                      -- corresponding to the extension type identified
                      -- by extnID
          }*/
        inta extn_end = 0;
    code = parse_data_element(raw_cert, DER_OCTET_STRING, idx, extension_end, &extn_end);
    if (code != SUCCESS) {
      return code;
    }

    inta extn_start = *idx;
    *idx = extn_end;

    if (extn_end != extension_end) {
      return TRAILING_DATA;
    }

    // TODO: Finish parsing contents.
  }

  // TODO: Finish parsing signatures.

  return SUCCESS;
}
