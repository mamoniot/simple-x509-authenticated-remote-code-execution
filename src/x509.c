#include "assert.h"
#include "time.h"
#include "string.h"

#include "basic.h"
#include "crypto.h"
#include "x509.h"

const byte DER_CONSTRUCTED = 0b00100000;
const byte DER_BOOLEAN = 1;
const byte DER_INTEGER = 2;
const byte DER_BITSTRING = DER_CONSTRUCTED | 3;
const byte DER_OCTET_STRING = DER_CONSTRUCTED | 4;
const byte DER_OID = 6;
const byte DER_SEQUENCE = DER_CONSTRUCTED | 16;
const byte DER_SET = DER_CONSTRUCTED | 17;
const byte DER_UTCTIME = 23;
const byte DER_GENERALIZEDTIME = 24;

const byte DER_LENGTH_FORM_MASK = 0b10000000;
const byte DER_LENGTH_INDEFINITE = 0b10000000;
const byte DER_LENGTH_RESERVED = 0b11111111;

const byte X509_ACCEPTED_VERSION = 2;

Code parse_any(byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_content_end,
               uint8* ret_identifier) {
  if (*idx >= parent_end) {
    return UNEXPECTED_END_OF_DATA;
  }

  uint8 identifier = raw_cert[*idx];
  *idx += 1;

  if (*idx >= parent_end) {
    return INVALID_END_OF_DATA;
  }

  uinta length_byte = raw_cert[*idx];

  if (length_byte == DER_LENGTH_INDEFINITE || length_byte == DER_LENGTH_RESERVED) {
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
  *ret_identifier = identifier;
  return OK;
}

Code parse_data_element(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                       uinta *ret_content_end) {
  uint8 identifier = 0;
  Code code = parse_any(raw_cert, idx, parent_end, ret_content_end, &identifier);
  if (code != OK) {
    return code;
  }
  if (identifier != expected_identifier) {
    return UNEXPECTED_IDENTIFIER;
  }
  return OK;
}

Code parse_optional_data(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                         uinta *ret_content_end) {
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

/*Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }*/
Code parse_time(byte *raw_cert, uinta *idx, uinta parent_end, time_t *ret_unix_ts) {
  const uinta UTCTIME_SIZE = 13;
  const uinta GENERALIZEDTIME_SIZE = 15;

  // A time_t can theoretically be 32 bits, which would be disatrous as all timestamps would
  // overflow in 2038. To compensate we will not support compilers that use 32 bit time_t.
  assert(sizeof(time_t) > 4);

  int ch;
#define CONVERT_NUM(n, m)                                                                          \
  {                                                                                                \
    ch = raw_cert[*idx];                                                                           \
    if (ch < '0' || ch > '9') {                                                                    \
      return INVALID_VALIDITY_TIME;                                                                \
    } else {                                                                                       \
      *idx += 1;                                                                                   \
      n += (ch - '0') * (m);                                                                       \
    }                                                                                              \
  }
#define CONVERT_2DIGIT(n)                                                                          \
  {                                                                                                \
    CONVERT_NUM(n, 10);                                                                            \
    CONVERT_NUM(n, 1);                                                                             \
  }

  struct tm utc = {0};
  uinta ts_end = 0;
  Code code = parse_optional_data(raw_cert, DER_UTCTIME, idx, parent_end, &ts_end);
  if (code != OK) {
    return code;
  }

  if (ts_end > 0) {
    if (*idx + UTCTIME_SIZE != ts_end) {
      return INVALID_VALIDITY_TIME;
    }

    CONVERT_2DIGIT(utc.tm_year);
    utc.tm_year += (utc.tm_year >= 50) ? 1900 : 2000;
  } else {
    // GeneralizedTime and UTCTime only differ by 2 YY characters.
    Code code = parse_data_element(raw_cert, DER_GENERALIZEDTIME, idx, parent_end, &ts_end);
    if (code != OK) {
      return code;
    }
    if (*idx + GENERALIZEDTIME_SIZE != ts_end) {
      return INVALID_VALIDITY_TIME;
    }

    CONVERT_NUM(utc.tm_year, 1000);
    CONVERT_NUM(utc.tm_year, 100);
    CONVERT_NUM(utc.tm_year, 10);
    CONVERT_NUM(utc.tm_year, 1);
  }
  CONVERT_2DIGIT(utc.tm_mon);
  CONVERT_2DIGIT(utc.tm_mday);
  CONVERT_2DIGIT(utc.tm_hour);
  CONVERT_2DIGIT(utc.tm_min);
  CONVERT_2DIGIT(utc.tm_sec);
  if (raw_cert[*idx] != 'Z') {
    return INVALID_VALIDITY_TIME;
  }

  struct tm pre_utc = utc;
  time_t ret = mktime(&utc);
  // If mktime altered the date then it was out of range and thus is invalid.
  if (ret < 0 || pre_utc.tm_year != utc.tm_year || pre_utc.tm_mon != utc.tm_mon ||
      pre_utc.tm_mday != utc.tm_mday || pre_utc.tm_hour != utc.tm_hour ||
      pre_utc.tm_min != utc.tm_min || pre_utc.tm_sec != utc.tm_sec) {
    return INVALID_VALIDITY_TIME;
  }

  *idx = ts_end;
  *ret_unix_ts = ret;
  return OK;
}

Code parse_alg_params(byte *raw_cert, uinta alg_oid_start, uinta alg_oid_end, uinta alg_id_end,
                      uinta *alg_idx) {
  uinta alg_oid_size = alg_oid_end - alg_oid_start;
  for_each_idx(const SupportedAlg, idx, alg, supported_algs, supported_algs_size) {
    if (alg->oid_size == alg_oid_size && memcmp(alg->oid, &raw_cert[alg_oid_start], alg_oid_size) == 0) {
      if (alg->parse_params(raw_cert, alg_oid_end, alg_id_end)) {
        *alg_idx = idx;
        return OK;
      } else {
        return INVALID_SIG_PARAMS;
      }
    }
  }
  return UNKNOWN_SIG_ID;
}

/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }*/
Code parse_alg_id(byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_id_start, uinta* ret_id_end, uinta* ret_oid_start, uinta* ret_oid_end) {
  *ret_id_start = *idx;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, ret_id_end);
  if (code != OK) {
    return code;
  }

  /*algorithm               OBJECT IDENTIFIER*/
  /*parameters              ANY DEFINED BY algorithm OPTIONAL*/
  // We skip parameter parsing for now since it is highly crypto-dependent.
  code = parse_data_element(raw_cert, DER_OID, idx, *ret_id_end, ret_oid_end);
  if (code != OK) {
    return code;
  }

  *ret_oid_start = *idx;
  *idx = *ret_id_end;

  return OK;
}

/*Name ::= CHOICE { -- only one possibility for now --
   rdnSequence  RDNSequence }*/
Code parse_name(byte *raw_cert, uinta *idx, uinta parent_end) {
  /*RDNSequence ::= SEQUENCE OF RelativeDistinguishedName*/
  uinta name_end = 0;
  Code code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &name_end);
  if (code != OK) {
    return code;
  }

  // This sequence may be empty.
  while (*idx < name_end) {
    /*RelativeDistinguishedName ::=
       SET SIZE (1..MAX) OF AttributeTypeAndValue*/
    uinta relative_name_end = 0;
    code = parse_data_element(raw_cert, DER_SET, idx, name_end, &relative_name_end);
    if (code != OK) {
      return code;
    }
    // TODO: Should we check for sorted ordering for this set?

    /*AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }*/
    // This set may not be empty.
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
      uint8 identifier = 0;
      code = parse_any(raw_cert, idx, attribute_end, &attribute_value_end, &identifier);
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

Code parse_x509(byte *raw_cert, uinta raw_cert_size, x509* ret_x509) {
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
  ret_x509->signed_data_start = *idx;

  uinta tbs_cert_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, cert_end, &tbs_cert_end);
  if (code != OK) {
    return code;
  }

  ret_x509->signed_data_end = tbs_cert_end;

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
  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &ret_x509->sig_id_start, &ret_x509->sig_id_end,
                      &ret_x509->sig_oid_start, &ret_x509->sig_oid_end);
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
  time_t not_before_ts = 0;
  code = parse_time(raw_cert, idx, validity_end, &not_before_ts);
  if (code != OK) {
    return code;
  }

  /*notAfter       Time*/
  time_t not_after_ts = 0;
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

  /*algorithm            AlgorithmIdentifier*/
  code = parse_alg_id(raw_cert, idx, public_key_info_end, &ret_x509->pub_key_id_start,
                      &ret_x509->pub_key_id_end, &ret_x509->pub_key_oid_start, &ret_x509->pub_key_oid_end);
  if (code != OK) {
    return code;
  }

  /*subjectPublicKey     BIT STRING*/
  code = parse_data_element(raw_cert, DER_BITSTRING, idx, public_key_info_end, &ret_x509->pub_key_end);
  if (code != OK) {
    return code;
  }
  if (*idx != public_key_info_end) {
    return TRAILING_DATA;
  }

  ret_x509->pub_key_start = *idx;
  *idx = ret_x509->pub_key_end;

  /*issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta issuer_uid_end = 0;
  code = parse_optional_data(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &issuer_uid_end);
  if (code != OK) {
    return code;
  }
  if (issuer_uid_end > 0) {
    // Issuer uids is currently unused.
    uinta issuer_uid_start = *idx;
    *idx = issuer_uid_end;
  }

  /*subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta subject_uid_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_BITSTRING, idx, tbs_cert_end, &subject_uid_end);
  if (code != OK) {
    return code;
  }
  if (subject_uid_end != IDX_NONE) {
    // Subject uid is currently unused.
    uinta subject_uid_start = *idx;
    *idx = subject_uid_end;
  }

  /*extensions      [3]  EXPLICIT Extensions OPTIONAL*/
  /*Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension*/
  uinta extensions_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &extensions_end);
  if (code != OK) {
    return code;
  }
  if (extensions_end != IDX_NONE) {
    while (*idx < extensions_end) {
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

      /*extnValue   OCTET STRING*/
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
  } else {
    ret_x509->skid_start = IDX_NONE;
    ret_x509->skid_end = IDX_NONE;
    ret_x509->akid_start = IDX_NONE;
    ret_x509->akid_end = IDX_NONE;
    ret_x509->key_cert_sign = false;
    ret_x509->path_len_constraint = 0;
  }

  // End of TBS certificate parsing.
  if (*idx != tbs_cert_end) {
    return TRAILING_DATA;
  }

  /*signatureAlgorithm   AlgorithmIdentifier*/
  // signatureAlgorithm must be identical to signature in the TBS cert, so we can simplify parsing.
  uinta sig_id_size = ret_x509->sig_id_end - ret_x509->sig_id_start;
  if (*idx + sig_id_size >= cert_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (memcmp(&raw_cert[ret_x509->sig_id_start], &raw_cert[*idx], sig_id_size) != 0) {
    return MISMATCHED_SIG_ID;
  }
  *idx += sig_id_size;

  /*signatureValue       BIT STRING*/
  code = parse_data_element(raw_cert, DER_BITSTRING, idx, cert_end, &ret_x509->sig_end);
  if (code != OK) {
    return code;
  }
  if (ret_x509->sig_end != cert_end) {
    return TRAILING_DATA;
  }

  ret_x509->sig_start = *idx;
  *idx = ret_x509->sig_end;

  return OK;
}
