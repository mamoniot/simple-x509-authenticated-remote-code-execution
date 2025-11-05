#include "assert.h"
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
  OK,
  UNEXPECTED_END_OF_DATA,
  UNEXPECTED_IDENTIFIER,
  INVALID_END_OF_DATA,
  INVALID_LENGTH_FORM,
  INVALID_LENGTH_TOO_LONG,
  TRAILING_DATA,
  INVALID_VERSION,
  INVALID_BOOLEAN,
} Code;

typedef struct {
  AlgID id;
} PublicKeyBuilder;

Code parse_data_element(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                       uinta *ret_content_end) {
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

  uinta length_byte = raw_cert[*idx];

  if (length_byte == DER_LENGTH_INDEFINITE ||
      length_byte == DER_LENGTH_RESERVED) {
    // Disallowed BER length type.
    return INVALID_LENGTH_FORM;
  }

  uinta length = 0;
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
  return OK;
}

Code parse_alg_params(byte *raw_cert, uinta alg_oid_start, uinta alg_oid_end, uinta alg_id_end,
                      PublicKeyBuilder *public_key);

/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }*/
Code parse_alg_id(byte *raw_cert, uinta *idx, uinta parent_end, PublicKeyBuilder *public_key) {
  uinta alg_id_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &alg_id_end);
  if (code != OK) {
    return code;
  }

  /*algorithm               OBJECT IDENTIFIER*/
  uinta alg_oid_end = 0;
  code = parse_data_element(raw_cert, DER_OID, idx, alg_id_end, &alg_oid_end);
  if (code != OK) {
    return code;
  }

  uinta alg_oid_start = *idx;
  *idx = alg_oid_end;

  /*parameters              ANY DEFINED BY algorithm OPTIONAL*/
  code = parse_alg_params(raw_cert, alg_oid_start, alg_oid_end, alg_id_end, public_key);
  if (code != OK) {
    return code;
  }

  *idx = alg_id_end;

  return OK;
}
/*subjectPublicKey     BIT STRING*/
Code parse_public_key(byte *raw_cert, uinta *idx, uinta parent_end, PublicKeyBuilder *public_key) {
  uinta public_key_end = 0;
  Code code = parse_data_element(raw_cert, DER_BITSTRING, idx, parent_end, &public_key_end);
  if (code != OK) {
    return code;
  }

  // TODO: Parse public key contents.
  uinta public_key_start = *idx;
  *idx = public_key_end;

  return OK;
}

/*Name ::= CHOICE { -- only one possibility for now --
   rdnSequence  RDNSequence }*/
Code parse_name(byte *raw_cert, uinta *idx, uinta parent_end) {
  /*RDNSequence ::= SEQUENCE OF RelativeDistinguishedName*/
  // TODO: It is not fully clear to me what length this sequence can actual be.
  uinta name_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &name_end);
  if (code != OK) {
    return code;
  }

  uinta relative_name_end = 0;
  while (relative_name_end < name_end) {
    /*RelativeDistinguishedName ::=
       SET SIZE (1..MAX) OF AttributeTypeAndValue*/
    code = parse_data_element(raw_cert, DER_SET, idx, name_end, &relative_name_end);
    if (code != OK) {
      return code;
    }
    // TODO: Should we check for sorted ordering for this set?

    /*AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }*/
    uinta attribute_end = 0;
    while (attribute_end < relative_name_end) {
      code = parse_data_element(raw_cert, DER_SEQUENCE, idx, relative_name_end, &attribute_end);
      if (code != OK) {
        return code;
      }

      /*AttributeType ::= OBJECT IDENTIFIER*/
      uinta attribute_type_end = 0;
      code = parse_data_element(raw_cert, DER_OID, idx, attribute_end, &attribute_type_end);
      if (code != OK) {
        return code;
      }

      uinta attribute_type_start = *idx;
      *idx = attribute_type_end;

      /*AttributeValue ::= ANY -- DEFINED BY AttributeType*/
      uinta attribute_value_end = 0;
      // TODO: Replace with choice call.
      code = parse_data_element(raw_cert, 111, idx, attribute_end, &attribute_value_end);
      if (code != OK) {
        return code;
      }
      if (attribute_end != attribute_value_end) {
        return TRAILING_DATA;
      }

      uinta attribute_value_start = *idx;
      *idx = attribute_value_end;
      // TODO: Finish parsing contents.
    }
    assert(*idx == relative_name_end);
  }
  assert(*idx == name_end);

  return OK;
}
/*Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }*/
Code parse_time(byte *raw_cert, uinta *idx, uinta parent_end, int64 *ret_unix_ts);

Code parse_optional_data(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end, uinta *ret_content_end) {
  Code code = parse_data_element(raw_cert, expected_identifier, idx, parent_end, ret_content_end);
  switch (code) {
  case UNEXPECTED_END_OF_DATA:
  case UNEXPECTED_IDENTIFIER:
  case OK:
    return OK;
  default:
    return code;
  }
}

Code parse_x509(byte *raw_cert, uinta raw_cert_size) {
  uinta idx_mem = 0;
  uinta *idx = &idx_mem;

  /*Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }*/
  uinta cert_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, raw_cert_size, &cert_end);
  if(code != OK) {
    return code;
  }
  if (raw_cert_size != cert_end) {
    return TRAILING_DATA;
  }

  /*tbsCertificate       TBSCertificate*/
  /* TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }*/
  uinta tbs_cert_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, cert_end, &tbs_cert_end);
  if (code != OK) {
    return code;
  }

  /*version         [0]  EXPLICIT Version DEFAULT v1*/
  uinta version_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &version_end);
  if (code != OK) {
    return code;
  }
  if (version_end - *idx != 1 || raw_cert[*idx] != X509_ACCEPTED_VERSION) {
    return INVALID_VERSION;
  }

  *idx = version_end;

  /*serialNumber         CertificateSerialNumber*/
  uinta serial_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &serial_end);
  if (code != OK) {
    return code;
  }

  // Currently we do not record the serial number of the cert. There is no current plan to use it.
  *idx = serial_end;

  /*signature            AlgorithmIdentifier*/
  PublicKeyBuilder public_key = {0};
  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &public_key);
  if (code != OK) {
    return code;
  }

  /*issuer               Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != OK) {
    return code;
  }

  /*validity             Validity*/
  /*Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }*/
  uinta validity_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &validity_end);
  if (code != OK) {
    return code;
  }

  /*notBefore      Time*/
  int64 not_before_ts = 0;
  code = parse_time(raw_cert, idx, validity_end, &not_before_ts);
  if (code != OK) {
    return code;
  }

  /*notAfter       Time*/
  int64 not_after_ts = 0;
  code = parse_time(raw_cert, idx, validity_end, &not_after_ts);
  if (code != OK) {
    return code;
  }
  if (validity_end != *idx) {
    return TRAILING_DATA;
  }

  /*subject              Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != OK) {
    return code;
  }

  /*subjectPublicKeyInfo SubjectPublicKeyInfo*/
  /*SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }*/
  uinta public_key_info_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &public_key_info_end);
  if (code != OK) {
    return code;
  }

  code = parse_alg_id(raw_cert, idx, public_key_info_end, &public_key);
  if (code != OK) {
    return code;
  }

  code = parse_public_key(raw_cert, idx, public_key_info_end, &public_key);
  if (code != OK) {
    return code;
  }
  if (*idx != public_key_info_end) {
    return TRAILING_DATA;
  }

  /*issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta issuer_uid_end = 0;
  code = parse_optional_data(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &issuer_uid_end);
  if (code != OK) {
    return code;
  }
  if (issuer_uid_end > 0) {
    uinta issuer_uid_start = *idx;
    *idx = issuer_uid_end;
  }

  /*subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta subject_uid_end = 0;
  code = parse_optional_data(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &subject_uid_end);
  if (code != OK) {
    return code;
  }
  if (subject_uid_end > 0) {
    uinta subject_uid_start = *idx;
    *idx = subject_uid_end;
  }

  /*extensions      [3]  EXPLICIT Extensions OPTIONAL*/
  /*Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension*/
  uinta extensions_end = 0;
  code = parse_optional_data(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &extensions_end);
  if (code != OK) {
    return code;
  }
  if (extensions_end > 0) {
    uinta extensions_start = *idx;
    *idx = extensions_end;
  }

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
    uinta extension_end = 0;
    code = parse_data_element(raw_cert, DER_SEQUENCE, idx, extensions_end, &extension_end);
    if (code != OK) {
      return code;
    }

    /*extnID      OBJECT IDENTIFIER*/
    uinta extn_oid_end = 0;
    code = parse_data_element(raw_cert, DER_OID, idx, extension_end, &extn_oid_end);
    if (code != OK) {
      return code;
    }

    uinta extn_oid_start = *idx;
    *idx = extn_oid_end;

    /*critical    BOOLEAN DEFAULT FALSE*/
    uinta critical_end = 0;
    // TODO: Replace with choice call.
    code = parse_optional_data(raw_cert, DER_BOOLEAN, idx, extension_end, &critical_end);
    if (code != OK) {
      return code;
    }

    bool critical = false;
    if (critical_end >= *idx + 1) {
      if (critical_end > *idx + 1 || raw_cert[*idx] > 1) {
        return INVALID_BOOLEAN;
      }
      critical = raw_cert[*idx] == 1;
      *idx = critical_end;
    }

    /*extnValue   OCTET STRING
                      -- contains the DER encoding of an ASN.1 value
                      -- corresponding to the extension type identified
                      -- by extnID
          }*/
    uinta extn_end = 0;
    code = parse_data_element(raw_cert, DER_OCTET_STRING, idx, extension_end, &extn_end);
    if (code != OK) {
      return code;
    }
    if (extn_end != extension_end) {
      return TRAILING_DATA;
    }

    uinta extn_start = *idx;
    *idx = extn_end;

    // TODO: Finish parsing contents.
  }
  assert(*idx == extensions_end);

  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &public_key);
  if (code != OK) {
    return code;
  }

  // TODO: Finish parsing signatures.

  return OK;
}
