#include "assert.h"
#include "basic.h"
#include "time.h"
#include "string.h"

#include "x509.h"

typedef struct {
  const byte *oid;
  uinta oid_size;
  // Can only be set to 0, 2, 3 (0b00, 0b10, 0b11).
  // 0b00 implies this extention can have any criticality.
  // 0b10 implies this extention must not be critical.
  // 0b11 implies this extention must be critical.
  int criticality;
  ParseCode (*parse_extn)(const byte *, uinta, uinta, x509Fields *);
} SupportedExtn;

// idx, ret_identifier and ret_content_end will be updated if this function returns PARSE_OK. The
// contents of idx, ret_identifier and ret_content_end are undefined and liable to change for any
// other return value.
//
// Ensures that *idx <= *ret_content_end <= parent_end after returning PARSE_OK.
ParseCode parse_any(const byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_content_end,
                    uint8 *ret_identifier) {
  if (*idx >= parent_end) {
    return UNEXPECTED_END_OF_DATA;
  }

  uint8 identifier = raw_cert[*idx];
  *idx += 1;

  if (*idx >= parent_end) {
    return UNEXPECTED_END_OF_DATA;
  }

  byte length_byte = raw_cert[*idx];

  if (length_byte == DER_LENGTH_INDEFINITE || length_byte == DER_LENGTH_RESERVED) {
    // Disallowed BER length type.
    return INVALID_LENGTH_FORM;
  }

  uinta length = 0;
  *idx += 1;

  if ((length_byte & DER_LENGTH_FORM_MASK) > 0) {
    // Definite long form length.
    int32 length_octets = length_byte & ~DER_LENGTH_FORM_MASK;
    if (*idx + length_octets > parent_end) {
      return UNEXPECTED_END_OF_DATA;
    }
    if (raw_cert[*idx] == 0) {
      // This check is not strictly necessary, but is still specified by DER.
      return INVALID_LENGTH_FORM;
    }
    if (length_octets > 8) {
      // We do not want to overflow on user input.
      return UNEXPECTED_END_OF_DATA;
    }

    for_each_lt(i, length_octets) {
      length = (length << 8) | raw_cert[*idx];
      *idx += 1;
    }

    if (length <= 127) {
      // Should have used short form.
      return INVALID_LENGTH_FORM;
    }
  } else {
    // Definite short form length.
    length = length_byte;
  }

  // This check must not overflow.
  if (length > parent_end - *idx) {
    return UNEXPECTED_END_OF_DATA;
  }

  *ret_content_end = *idx + length;
  *ret_identifier = identifier;
  return PARSE_OK;
}

ParseCode parse_data_element(const byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                       uinta *ret_content_end) {
  uint8 identifier = 0;
  ParseCode code = parse_any(raw_cert, idx, parent_end, ret_content_end, &identifier);
  if (code != PARSE_OK) {
    return code;
  }
  if (identifier != expected_identifier) {
    return UNEXPECTED_IDENTIFIER;
  }
  return PARSE_OK;
}

ParseCode parse_null(const byte *raw_cert, uinta *idx, uinta parent_end) {
  uint8 identifier = 0;
  if (*idx + 2 > parent_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (raw_cert[*idx] != 0x05) {
    return UNEXPECTED_IDENTIFIER;
  }
  if (raw_cert[*idx + 1] != 0x00) {
    return INVALID_LENGTH_FORM;
  }
  *idx += 2;
  return PARSE_OK;
}

// Similar to parse_data_element, except this will return CERT_OK and not update idx and
// ret_content_end if a field of type expected_identifier could not be found at raw_cert[idx].
//
// idx and ret_content_end may be updated if this function returns PARSE_OK. The
// contents of idx and ret_content_end are undefined and liable to change for any
// other return value.
//
// Ensures that *idx <= *ret_content_end <= parent_end after returning PARSE_OK.
ParseCode parse_optional_data(const byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                         uinta *ret_content_end) {
  uinta pre_idx = *idx;
  uinta pre_end = *ret_content_end;
  ParseCode code = parse_data_element(raw_cert, expected_identifier, idx, parent_end, ret_content_end);
  switch (code) {
  case UNEXPECTED_END_OF_DATA:
  case UNEXPECTED_IDENTIFIER:
    // Nondeterministic rollback.
    *idx = pre_idx;
    *ret_content_end = pre_end;
  case PARSE_OK:
    return PARSE_OK;
  default:
    return code;
  }
}

// idx and ret_bool will be updated if this function returns PARSE_OK. The
// contents of idx and ret_bool are undefined and liable to change for any
// other return value.
//
// Ensures that *idx <= parent_end after returning PARSE_OK.
ParseCode parse_default_bool(const byte *raw_cert, uinta *idx, uinta parent_end, bool *ret_bool) {
  /*cA               BOOLEAN DEFAULT FALSE*/
  uinta bool_end = IDX_NONE;
  ParseCode code = parse_optional_data(raw_cert, DER_BOOLEAN, idx, parent_end, &bool_end);
  if (code != PARSE_OK) {
    return code;
  }

  if (bool_end != IDX_NONE) {
    if (bool_end != *idx + 1 || raw_cert[*idx] != 0xff) {
      return INVALID_BOOLEAN;
    }

    *ret_bool = true;
    *idx = bool_end;
  } else {
    *ret_bool = false;
  }

  return PARSE_OK;
}

// idx and ret_content_end will be updated if this function returns PARSE_OK. The
// contents of idx and ret_content_end are undefined and liable to change for any
// other return value.
//
// Ensures that *idx <= *ret_content_end <= parent_end after returning PARSE_OK.
//
// There is no modern public key algorithm that has a key or signature size that does not align with
// 8 bits. So we can safely discard the certificate if we encounter a bitstring with unused bits.
ParseCode parse_bitstring_no_unused(const byte *raw_cert, uinta *idx, uinta parent_end,
                                     uinta *ret_content_end) {
  /*subjectPublicKey     BIT STRING*/
  ParseCode code = parse_data_element(raw_cert, DER_BITSTRING, idx, parent_end, ret_content_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (*idx >= *ret_content_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (raw_cert[*idx] != 0) {
    return INVALID_BITSTRING;
  }

  *idx += 1;
  return PARSE_OK;
}

/*basicConstraint  ::=  SEQUENCE  {
  cA               BOOLEAN DEFAULT FALSE,
  pathLenContraint INTEGER DEFAULT INFINITY,
}*/
ParseCode parse_basic_constraint(const byte *raw_cert, uinta idx, uinta extn_end,
                                  x509Fields *ret_fields) {
  uinta constraint_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, &idx, extn_end, &constraint_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*cA               BOOLEAN DEFAULT FALSE*/
  code = parse_default_bool(raw_cert, &idx, constraint_end, &ret_fields->key_cert_sign);
  if (code != PARSE_OK) {
    return code;
  }

  if (ret_fields->key_cert_sign) {
    /*pathLenContraint INTEGER OPTIONAL*/
    uinta path_end = IDX_NONE;
    code = parse_optional_data(raw_cert, DER_INTEGER, &idx, constraint_end, &path_end);
    if (code != PARSE_OK) {
      return code;
    }

    if (path_end != IDX_NONE) {
      if (idx == path_end) {
        return UNEXPECTED_END_OF_DATA;
      }
      if ((raw_cert[idx] & 0x80) > 0 || path_end - idx > 4) {
        // Negative values are not permitted for path lengths.
        return INVALID_INTEGER;
      }
      while (idx < path_end) {
        ret_fields->path_len_constraint = (ret_fields->path_len_constraint << 8) | cast(uint32, raw_cert[idx]);
        idx += 1;
      }
      idx = path_end;
    } else {
      ret_fields->path_len_constraint = MAX_UINT32;
    }
  }
  if (idx != extn_end) {
    return TRAILING_DATA;
  }

  return PARSE_OK;
}

/*AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }*/
ParseCode parse_akid(const byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  uinta akid_seq_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, &idx, extn_end, &akid_seq_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (akid_seq_end != extn_end) {
    return TRAILING_DATA;
  }

  /*keyIdentifier             [0] KeyIdentifier           OPTIONAL*/
  /*KeyIdentifier ::= OCTET STRING*/
  ret_fields->akid_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_0, &idx, akid_seq_end, &ret_fields->akid_end);
  if (code != PARSE_OK) {
    return code;
  }

  if (ret_fields->akid_end != IDX_NONE) {
    ret_fields->akid_start = idx;
    idx = ret_fields->akid_end;
  }

  /*authorityCertIssuer       [1] GeneralNames            OPTIONAL*/
  uinta aci_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_1 | DER_CONSTRUCTED, &idx, akid_seq_end, &aci_end);
  if (code != PARSE_OK) {
    return code;
  }

  // NOTE: This do not parse general names nor certificate serial numbers in the akid extensions.
  // I decided not to support either since both near meaningless withinthe context of a self-signed
  // TCP code-signing context, and are much more error prone than the high-entropy key identifier.
  if (aci_end != IDX_NONE) {
    // This is where general names would be parsed.
    idx = aci_end;
  }

  /*authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL*/
  uinta acsn_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_2, &idx, akid_seq_end, &acsn_end);
  if (code != PARSE_OK) {
    return code;
  }

  if (acsn_end != IDX_NONE) {
    // This is where certificate serial number would be parsed.
    idx = acsn_end;
  }

  if (idx != extn_end) {
    return TRAILING_DATA;
  }

  return PARSE_OK;
}

/*SubjectKeyIdentifier ::= KeyIdentifier*/
ParseCode parse_skid(const byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  ParseCode code = parse_data_element(raw_cert, DER_OCTET_STRING, &idx, extn_end, &ret_fields->skid_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (ret_fields->skid_end != extn_end) {
    return TRAILING_DATA;
  }

  ret_fields->skid_start = idx;
  return PARSE_OK;
}

/*KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }*/
// This function assumes that ret_fields->key_usage_flags is already initialized and will bitwise or
// the new usages onto it.
ParseCode parse_key_usage(const byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  uinta usage_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_BITSTRING, &idx, extn_end, &usage_end);
  if (code != PARSE_OK) {
    return code;
  }
  // Bitstring must contain 2 or 3 bytes.
  if (usage_end - idx <= 1) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (usage_end != extn_end || usage_end - idx > 3) {
    return TRAILING_DATA;
  }

  // Validate the bitstring length.
  /*When DER encoding a named bit list, trailing zeros MUST be omitted.  That is, the encoded value
   * ends with the last named bit that is set to one.*/
  if (raw_cert[idx] >= 8) {
    return INVALID_BITSTRING;
  }
  uint8 last_set_bit = 0x80u >> (7 - raw_cert[idx]);
  // This intentionally overflows.
  uint8 unused_bits = last_set_bit - 1;
  if ((raw_cert[usage_end - 1] & last_set_bit) == 0 ||
      (raw_cert[usage_end - 1] & unused_bits) > 0) {
    return INVALID_BITSTRING;
  }

  ret_fields->has_key_usage = true;
  // This logic only works because we use the same exact bit flags as this extension specifies.
  ret_fields->key_usage_flags |= cast(uint32, raw_cert[idx + 1]);
  if (idx + 2 < usage_end) {
    ret_fields->key_usage_flags |= cast(uint32, raw_cert[idx + 2]) << 1;
  }
  return PARSE_OK;
}

/*ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId*/
// This function assumes that ret_fields->key_usage_flags is already initialized and will bitwise or
// the new usages onto it.
ParseCode parse_ext_key_usage(const byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  const byte KP_OID[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x00};

  uinta usage_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, &idx, extn_end, &usage_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (usage_end != extn_end) {
    return TRAILING_DATA;
  }

  /*KeyPurposeId ::= OBJECT IDENTIFIER*/
  while (idx < usage_end) {
    uinta purpose_end = 0;
    code = parse_data_element(raw_cert, DER_OID, &idx, usage_end, &purpose_end);
    if (code != PARSE_OK) {
      return code;
    }

    // All official extended key usage oids start with the same prefix.
    if (purpose_end - idx == sizeof(KP_OID) &&
        memcmp(&raw_cert[idx], KP_OID, sizeof(KP_OID) - 1) == 0) {
      switch (raw_cert[purpose_end - 1]) {
      case 0x00:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_ANY_EXTENDED;
        break;
      case 0x01:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_SERVER_AUTH;
        break;
      case 0x02:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_CLIENT_AUTH;
        break;
      case 0x03:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_CODE_SIGNING;
        break;
      case 0x04:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_EMAIL_PROTECT;
        break;
      case 0x08:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_TIMESTAMP;
        break;
      case 0x09:
        ret_fields->key_usage_flags |= KEY_USAGE_FLAG_OCSP_SIGN;
        break;
      default:
        // Unknown extended key usage oid, ignore it.
        break;
      }
    }

    idx = purpose_end;
  }
  assert(idx == usage_end);

  ret_fields->has_ext_key_usage = 1;
  return PARSE_OK;
}

#define TABULATE(...) {__VA_ARGS__}
// Macro to automatically and correctly declare new supported extensions.
#define DECL_EXTN(name, c, oid)                                                                    \
  static const byte MACRO_CAT(name, _oid)[] = oid;                                                 \
  static const SupportedExtn name = {MACRO_CAT(name, _oid), sizeof(MACRO_CAT(name, _oid)), c,      \
                                     MACRO_CAT(parse_, name)};

DECL_EXTN(basic_constraint, 0b11, TABULATE(0x55, 0x1d, 0x13));
DECL_EXTN(akid, 0b10, TABULATE(0x55, 0x1d, 0x23));
DECL_EXTN(skid, 0b10, TABULATE(0x55, 0x1d, 0x0e));
DECL_EXTN(key_usage, 0b00, TABULATE(0x55, 0x1d, 0x0f));
DECL_EXTN(ext_key_usage, 0b00, TABULATE(0x55, 0x1d, 0x25));

// List of extensions this library supports. It is designed to be easy to extend using the above
// macros.
const SupportedExtn supported_etxns[] = {basic_constraint, akid, skid, key_usage, ext_key_usage};
const uinta supported_etxns_size = sizeof(supported_etxns) / sizeof(supported_etxns[0]);

// Sets the default values of all extension associated fields in ret_fields.
// This function must be updated with any newly support extension fields. Otherwise ret_fields
// of the function parse_x509 may not be fully initialized even after returning PARSE_OK.
void assign_default_extensions(x509Fields* ret_fields) {
  ret_fields->skid_start = IDX_NONE;
  ret_fields->skid_end = IDX_NONE;
  ret_fields->akid_start = IDX_NONE;
  ret_fields->akid_end = IDX_NONE;
  ret_fields->key_cert_sign = false;
  ret_fields->path_len_constraint = 0;
  ret_fields->has_key_usage = false;
  ret_fields->has_ext_key_usage = false;
  ret_fields->key_usage_flags = 0;
}

/*Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }*/
// If CERT_OK is returned, idx will point to the byte after the consumed time.
ParseCode parse_time(const byte *raw_cert, uinta *idx, uinta parent_end, time_t *ret_unix_ts) {
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
  uinta ts_end = IDX_NONE;
  ParseCode code = parse_optional_data(raw_cert, DER_UTCTIME, idx, parent_end, &ts_end);
  if (code != PARSE_OK) {
    return code;
  }

  if (ts_end != IDX_NONE) {
    if (*idx + UTCTIME_SIZE != ts_end) {
      return INVALID_VALIDITY_TIME;
    }

    CONVERT_2DIGIT(utc.tm_year);
    utc.tm_year += cast(int, utc.tm_year < 50) * 100;
  } else {
    // GeneralizedTime and UTCTime only differ by 2 YY characters.
    ParseCode code = parse_data_element(raw_cert, DER_GENERALIZEDTIME, idx, parent_end, &ts_end);
    if (code != PARSE_OK) {
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

  // Convert month. This can underflow with invalid user input but timegm will catch that.
  utc.tm_mon -= 1;

  struct tm pre_utc = utc;
  time_t ret = timegm(&utc);
  // If mktime altered the date then it was out of range and thus is invalid.
  if (ret < 0 || pre_utc.tm_year != utc.tm_year || pre_utc.tm_mon != utc.tm_mon ||
      pre_utc.tm_mday != utc.tm_mday || pre_utc.tm_hour != utc.tm_hour ||
      pre_utc.tm_min != utc.tm_min || pre_utc.tm_sec != utc.tm_sec) {
    return INVALID_VALIDITY_TIME;
  }

  *idx = ts_end;
  *ret_unix_ts = ret;
  return PARSE_OK;
}

/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }*/
// If CERT_OK is returned, idx will point to the byte after the algorithm identifier.
ParseCode parse_alg_id(const byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_id_start,
                       uinta *ret_id_end, uinta *ret_oid_start, uinta *ret_oid_end) {
  *ret_id_start = *idx;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, ret_id_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*algorithm               OBJECT IDENTIFIER*/
  /*parameters              ANY DEFINED BY algorithm OPTIONAL*/
  // We skip parameter parsing for now since it is highly crypto-dependent.
  code = parse_data_element(raw_cert, DER_OID, idx, *ret_id_end, ret_oid_end);
  if (code != PARSE_OK) {
    return code;
  }

  *ret_oid_start = *idx;
  *idx = *ret_id_end;

  return PARSE_OK;
}

/*Name ::= CHOICE { -- only one possibility for now --
   rdnSequence  RDNSequence }*/
// If CERT_OK is returned, idx will point to the byte after the names sequence.
//
// NOTE: This function currently only parses name sequences and increments idx on success. None of
// the parse fields are used or recorded currently, as they are near meaningless in the context of
// TCP code signing. If I were to continue development I would add a _issuer_start, _issuer_end,
// subject_start and subject_end member to the x509Fields struct for every single AttributeType that
// the names sequence may contain.
ParseCode parse_name(const byte *raw_cert, uinta *idx, uinta parent_end) {
  /*RDNSequence ::= SEQUENCE OF RelativeDistinguishedName*/
  uinta name_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &name_end);
  if (code != PARSE_OK) {
    return code;
  }

  // This sequence may be empty.
  while (*idx < name_end) {
    /*RelativeDistinguishedName ::=
       SET SIZE (1..MAX) OF AttributeTypeAndValue*/
    uinta relative_name_end = 0;
    code = parse_data_element(raw_cert, DER_SET, idx, name_end, &relative_name_end);
    if (code != PARSE_OK) {
      return code;
    }

    /*AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }*/
    // This set may not be empty.
    uinta attribute_end = 0;
    while (attribute_end < relative_name_end) {
      code = parse_data_element(raw_cert, DER_SEQUENCE, idx, relative_name_end, &attribute_end);
      if (code != PARSE_OK) {
        return code;
      }

      /*AttributeType ::= OBJECT IDENTIFIER*/
      uinta attribute_type_end = 0;
      code = parse_data_element(raw_cert, DER_OID, idx, attribute_end, &attribute_type_end);
      if (code != PARSE_OK) {
        return code;
      }

      uinta attribute_type_start = *idx;
      *idx = attribute_type_end;

      /*AttributeValue ::= ANY -- DEFINED BY AttributeType*/
      uinta attribute_value_end = 0;
      uint8 identifier = 0;
      code = parse_any(raw_cert, idx, attribute_end, &attribute_value_end, &identifier);
      if (code != PARSE_OK) {
        return code;
      }
      if (attribute_end != attribute_value_end) {
        return TRAILING_DATA;
      }

      uinta attribute_value_start = *idx;
      *idx = attribute_value_end;

      // This is where name attributes and values would be used and recorded if they were supported.
    }
    assert(*idx == relative_name_end);
  }
  assert(*idx == name_end);

  return PARSE_OK;
}

ParseCode parse_x509(const byte *raw_cert, uinta raw_cert_size, x509Fields* ret_fields) {
  uinta idx_mem = 0;
  uinta *idx = &idx_mem;

  /*Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }*/
  uinta cert_end = 0;
  ParseCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, raw_cert_size, &cert_end);
  if(code != PARSE_OK) {
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
  ret_fields->signed_data_start = *idx;

  uinta tbs_cert_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, cert_end, &tbs_cert_end);
  if (code != PARSE_OK) {
    return code;
  }

  ret_fields->signed_data_end = tbs_cert_end;

  /*version         [0]  EXPLICIT Version DEFAULT v1*/
  // I hate that this field is double-packed for seemingly no reason.
  uinta explicit_end = 0;
  code = parse_data_element(raw_cert, DER_EXPLICIT_0, idx, tbs_cert_end, &explicit_end);
  if (code != PARSE_OK) {
    return code;
  }

  uinta version_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, explicit_end, &version_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (version_end - *idx != 1 || raw_cert[*idx] != X509_ACCEPTED_VERSION) {
    return INVALID_VERSION;
  }
  if (version_end != explicit_end) {
    return TRAILING_DATA;
  }

  *idx = version_end;

  /*serialNumber         CertificateSerialNumber*/
  uinta serial_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &ret_fields->cert_serial_end);
  if (code != PARSE_OK) {
    return code;
  }

  ret_fields->cert_serial_start = *idx;
  *idx = ret_fields->cert_serial_end;

  /*signature            AlgorithmIdentifier*/
  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &ret_fields->sig_id_start, &ret_fields->sig_id_end,
                      &ret_fields->sig_oid_start, &ret_fields->sig_oid_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*issuer               Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*validity             Validity*/
  /*Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }*/
  uinta validity_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &validity_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*notBefore      Time*/
  code = parse_time(raw_cert, idx, validity_end, &ret_fields->not_before);
  if (code != PARSE_OK) {
    return code;
  }

  /*notAfter       Time*/
  code = parse_time(raw_cert, idx, validity_end, &ret_fields->not_after);
  if (code != PARSE_OK) {
    return code;
  }
  if (*idx != validity_end) {
    return TRAILING_DATA;
  }

  /*subject              Name*/
  code = parse_name(raw_cert, idx, tbs_cert_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*subjectPublicKeyInfo SubjectPublicKeyInfo*/
  /*SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }*/
  uinta public_key_info_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, tbs_cert_end, &public_key_info_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*algorithm            AlgorithmIdentifier*/
  code = parse_alg_id(raw_cert, idx, public_key_info_end, &ret_fields->pub_key_id_start,
                      &ret_fields->pub_key_id_end, &ret_fields->pub_key_oid_start, &ret_fields->pub_key_oid_end);
  if (code != PARSE_OK) {
    return code;
  }

  /*subjectPublicKey     BIT STRING*/
  code = parse_bitstring_no_unused(raw_cert, idx, public_key_info_end,
                                   &ret_fields->pub_key_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (ret_fields->pub_key_end != public_key_info_end) {
    return TRAILING_DATA;
  }

  ret_fields->pub_key_start = *idx;
  *idx = ret_fields->pub_key_end;

  /*issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta issuer_uid_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_1, idx, tbs_cert_end, &issuer_uid_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (issuer_uid_end != IDX_NONE) {
    // Issuer uid is currently unused.
    // uinta issuer_uid_start = *idx;
    *idx = issuer_uid_end;
  }

  /*subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL*/
  uinta subject_uid_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_2, idx, tbs_cert_end, &subject_uid_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (subject_uid_end != IDX_NONE) {
    // Subject uid is currently unused.
    // uinta subject_uid_start = *idx;
    *idx = subject_uid_end;
  }

  /*extensions      [3]  EXPLICIT Extensions OPTIONAL*/
  uinta explicit_3_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_EXPLICIT_3, idx, tbs_cert_end, &explicit_3_end);
  if (code != PARSE_OK) {
    return code;
  }

  // Assign default values to be overwritten.
  assign_default_extensions(ret_fields);

  if (explicit_3_end != IDX_NONE) {
    /*Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension*/
    uinta extensions_end = 0;
    code = parse_data_element(raw_cert, DER_SEQUENCE, idx, explicit_3_end, &extensions_end);
    if (code != PARSE_OK) {
      return code;
    }
    if (extensions_end != explicit_3_end) {
      return TRAILING_DATA;
    }

    const byte *extn_oids[MAX_EXTN] = {0};
    uinta extn_oid_sizes[MAX_EXTN] = {0};
    uinta extn_oid_list_size = 0;

    while (*idx < extensions_end) {
      if (extn_oid_list_size >= MAX_EXTN) {
        return EXCEEDS_MAX_EXTNS;
      }
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
      if (code != PARSE_OK) {
        return code;
      }

      /*extnID      OBJECT IDENTIFIER*/
      uinta extn_oid_end = 0;
      code = parse_data_element(raw_cert, DER_OID, idx, extension_end, &extn_oid_end);
      if (code != PARSE_OK) {
        return code;
      }

      uinta extn_oid_start = *idx;
      *idx = extn_oid_end;

      /*critical    BOOLEAN DEFAULT FALSE*/
      bool critical = false;
      code = parse_default_bool(raw_cert, idx, extension_end, &critical);
      if (code != PARSE_OK) {
        return code;
      }

      /*extnValue   OCTET STRING*/
      uinta extn_end = 0;
      code = parse_data_element(raw_cert, DER_OCTET_STRING, idx, extension_end, &extn_end);
      if (code != PARSE_OK) {
        return code;
      }
      if (extn_end != extension_end) {
        return TRAILING_DATA;
      }

      const byte *extn_oid = &raw_cert[extn_oid_start];
      uinta extn_oid_size = extn_oid_end - extn_oid_start;

      // Check if we have already seen this extn oid.
      // Assigning 128-bit hash-based uuids to each oid would be optimally scalable but very
      // complicated. Linear lookup is better unless MAX_EXTN is increased by an order of magnitude.
      for_each_lt(i, extn_oid_list_size) {
        if (memeq(extn_oids[i], extn_oid_sizes[i], extn_oid, extn_oid_size)) {
          return DUPLICATE_EXTNS;
        }
      }
      extn_oids[extn_oid_list_size] = extn_oid;
      extn_oid_sizes[extn_oid_list_size] = extn_oid_size;
      extn_oid_list_size += 1;

      bool critical_fail = critical;
      for_each_in(const SupportedExtn, s_extn, supported_etxns, supported_etxns_size) {
        if (memeq(s_extn->oid, s_extn->oid_size, extn_oid, extn_oid_size)) {
          if ((s_extn->criticality & 0b10) > 0 && (s_extn->criticality & 0b01) != cast(int, critical)) {
            return INVALID_CRITICALITY;
          }

          code = s_extn->parse_extn(raw_cert, *idx, extn_end, ret_fields);
          if (code != PARSE_OK) {
            return code;
          }

          critical_fail = false;
          break;
        }
      }
      if (critical_fail) {
        return UNRECOGNIZED_CRITICAL_EXTN;
      }
      *idx = extn_end;
    }
    assert(*idx == extensions_end);
  }

  // End of TBS certificate parsing.
  if (*idx != tbs_cert_end) {
    return TRAILING_DATA;
  }

  /*signatureAlgorithm   AlgorithmIdentifier*/
  // signatureAlgorithm must be identical to signature in the TBS cert, so we can simplify parsing.
  uinta sig_id_size = ret_fields->sig_id_end - ret_fields->sig_id_start;
  if (*idx + sig_id_size >= cert_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (memcmp(&raw_cert[ret_fields->sig_id_start], &raw_cert[*idx], sig_id_size) != 0) {
    return MISMATCHED_SIG_ID;
  }
  *idx += sig_id_size;

  /*signatureValue       BIT STRING*/
  code = parse_bitstring_no_unused(raw_cert, idx, cert_end, &ret_fields->sig_end);
  if (code != PARSE_OK) {
    return code;
  }
  if (ret_fields->sig_end != cert_end) {
    return TRAILING_DATA;
  }

  ret_fields->sig_start = *idx;
  *idx = ret_fields->sig_end;

  return PARSE_OK;
}
