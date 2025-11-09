#include "assert.h"
#include "basic.h"
#include "time.h"
#include "string.h"

#include "x509.h"


typedef struct {
  const byte *oid;
  uinta oid_size;
  // 0b00 implies extn can have any criticality.
  // 0b10 implies extn must not be critical.
  // 0b11 implies extn must be critical.
  int criticality;
  StatusCode (*parse_extn)(byte *, uinta, uinta, x509Fields *);
} SupportedExtn;


StatusCode parse_any(byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_content_end,
               uint8* ret_identifier) {
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
  return OK;
}

StatusCode parse_data_element(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                       uinta *ret_content_end) {
  uint8 identifier = 0;
  StatusCode code = parse_any(raw_cert, idx, parent_end, ret_content_end, &identifier);
  if (code != OK) {
    return code;
  }
  if (identifier != expected_identifier) {
    return UNEXPECTED_IDENTIFIER;
  }
  return OK;
}

StatusCode parse_null(byte *raw_cert, uinta *idx, uinta parent_end) {
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
  return OK;
}

StatusCode parse_optional_data(byte *raw_cert, uint8 expected_identifier, uinta *idx, uinta parent_end,
                         uinta *ret_content_end) {
  uinta pre_idx = *idx;
  uinta pre_end = *ret_content_end;
  StatusCode code = parse_data_element(raw_cert, expected_identifier, idx, parent_end, ret_content_end);
  switch (code) {
  case UNEXPECTED_END_OF_DATA:
  case UNEXPECTED_IDENTIFIER:
    // Nondeterministic rollback.
    *idx = pre_idx;
    *ret_content_end = pre_end;
  case OK:
    return OK;
  default:
    return code;
  }
}

StatusCode parse_default_bool(byte *raw_cert, uinta *idx, uinta parent_end, bool *ret_bool) {
  /*cA               BOOLEAN DEFAULT FALSE*/
  uinta bool_end = IDX_NONE;
  StatusCode code = parse_optional_data(raw_cert, DER_BOOLEAN, idx, parent_end, &bool_end);
  if (code != OK) {
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

  return OK;
}

// There is no modern public key algorithm that has a key or signature size that does not align with
// 8 bits. So we can safely discard the certificate if we encounter a bitstring with unused bits.
StatusCode parse_bitstring_no_unused(byte *raw_cert, uinta *idx, uinta parent_end,
                                     uinta *ret_content_end) {
  /*subjectPublicKey     BIT STRING*/
  StatusCode code = parse_data_element(raw_cert, DER_BITSTRING, idx, parent_end, ret_content_end);
  if (code != OK) {
    return code;
  }
  if (*idx >= *ret_content_end) {
    return UNEXPECTED_END_OF_DATA;
  }
  if (raw_cert[*idx] != 0) {
    return TRAILING_DATA;
  }

  *idx += 1;
  return OK;
}

/*basicConstraint  ::=  SEQUENCE  {
  cA               BOOLEAN DEFAULT FALSE,
  pathLenContraint INTEGER DEFAULT INFINITY,
}*/
StatusCode parse_basic_constraint(byte *raw_cert, uinta idx, uinta extn_end,
                                  x509Fields *ret_fields) {
  uinta constraint_end = 0;
  StatusCode code = parse_data_element(raw_cert, DER_SEQUENCE, &idx, extn_end, &constraint_end);
  if (code != OK) {
    return code;
  }

  /*cA               BOOLEAN DEFAULT FALSE*/
  code = parse_default_bool(raw_cert, &idx, constraint_end, &ret_fields->key_cert_sign);
  if (code != OK) {
    return code;
  }

  if (ret_fields->key_cert_sign) {
    /*pathLenContraint INTEGER DEFAULT INFINITY*/
    uinta path_end = IDX_NONE;
    code = parse_optional_data(raw_cert, DER_INTEGER, &idx, constraint_end, &path_end);
    if (code != OK) {
      return code;
    }

    if (path_end != IDX_NONE) {
      // TODO: Handle path_len_constraint
      idx = path_end;
    }
  }
  if (idx != extn_end) {
    return TRAILING_DATA;
  }

  return OK;
}

/*AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }*/
StatusCode parse_akid(byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  uinta akid_seq_end = 0;
  StatusCode code = parse_data_element(raw_cert, DER_SEQUENCE, &idx, extn_end, &akid_seq_end);
  if (code != OK) {
    return code;
  }
  if (akid_seq_end != extn_end) {
    return TRAILING_DATA;
  }

  /*keyIdentifier             [0] KeyIdentifier           OPTIONAL*/
  /*KeyIdentifier ::= OCTET STRING*/
  ret_fields->akid_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_0, &idx, akid_seq_end, &ret_fields->akid_end);
  if (code != OK) {
    return code;
  }

  if (ret_fields->akid_end != IDX_NONE) {
    ret_fields->akid_start = idx;
    idx = ret_fields->akid_end;
  }

  /*authorityCertIssuer       [1] GeneralNames            OPTIONAL*/
  uinta aci_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_1, &idx, akid_seq_end, &aci_end);
  if (code != OK) {
    return code;
  }

  if (aci_end != IDX_NONE) {
    // TODO: Parse general names.
    idx = aci_end;
  }

  /*authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL*/
  uinta acsn_end = IDX_NONE;
  code = parse_optional_data(raw_cert, DER_IMPLICIT_2, &idx, akid_seq_end, &acsn_end);
  if (code != OK) {
    return code;
  }

  if (acsn_end != IDX_NONE) {
    // TODO: Use serial number.
    idx = acsn_end;
  }

  if (idx != extn_end) {
    return TRAILING_DATA;
  }

  return OK;
}

/*SubjectKeyIdentifier ::= KeyIdentifier*/
StatusCode parse_skid(byte *raw_cert, uinta idx, uinta extn_end, x509Fields *ret_fields) {
  StatusCode code = parse_data_element(raw_cert, DER_OCTET_STRING, &idx, extn_end, &ret_fields->skid_end);
  if (code != OK) {
    return code;
  }
  if (ret_fields->skid_end != extn_end) {
    return TRAILING_DATA;
  }

  ret_fields->skid_start = idx;
  return OK;
}


#define TABULATE(...) {__VA_ARGS__}
#define DECL_EXTN(name, c, oid)                                                                    \
  static const byte MACRO_CAT(name, _oid)[] = oid;                                                 \
  static const SupportedExtn name = {MACRO_CAT(name, _oid), sizeof(MACRO_CAT(name, _oid)), c,      \
                                     MACRO_CAT(parse_, name)};

DECL_EXTN(basic_constraint, 0b11, TABULATE(0x55, 0x1d, 0x13));
DECL_EXTN(akid, 0b10, TABULATE(0x55, 0x1d, 0x23));
DECL_EXTN(skid, 0b10, TABULATE(0x55, 0x1d, 0x0e));

const SupportedExtn supported_etxns[] = {basic_constraint, akid, skid};
const uinta supported_etxns_size = sizeof(supported_etxns) / sizeof(supported_etxns[0]);


/*Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }*/
StatusCode parse_time(byte *raw_cert, uinta *idx, uinta parent_end, time_t *ret_unix_ts) {
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
  StatusCode code = parse_optional_data(raw_cert, DER_UTCTIME, idx, parent_end, &ts_end);
  if (code != OK) {
    return code;
  }

  if (ts_end > 0) {
    if (*idx + UTCTIME_SIZE != ts_end) {
      return INVALID_VALIDITY_TIME;
    }

    CONVERT_2DIGIT(utc.tm_year);
    utc.tm_year += cast(int, utc.tm_year < 50) * 100;
  } else {
    // GeneralizedTime and UTCTime only differ by 2 YY characters.
    StatusCode code = parse_data_element(raw_cert, DER_GENERALIZEDTIME, idx, parent_end, &ts_end);
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

  // Convert month. This can overflow but timegm will catch that.
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
  return OK;
}

/*AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }*/
StatusCode parse_alg_id(byte *raw_cert, uinta *idx, uinta parent_end, uinta *ret_id_start, uinta* ret_id_end, uinta* ret_oid_start, uinta* ret_oid_end) {
  *ret_id_start = *idx;
  StatusCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, ret_id_end);
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
StatusCode parse_name(byte *raw_cert, uinta *idx, uinta parent_end) {
  /*RDNSequence ::= SEQUENCE OF RelativeDistinguishedName*/
  uinta name_end = 0;
  StatusCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, parent_end, &name_end);
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

StatusCode parse_x509(byte *raw_cert, uinta raw_cert_size, x509Fields* ret_fields) {
  uinta idx_mem = 0;
  uinta *idx = &idx_mem;

  /*Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }*/
  uinta cert_end = 0;
  StatusCode code = parse_data_element(raw_cert, DER_SEQUENCE, idx, raw_cert_size, &cert_end);
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
  ret_fields->signed_data_start = *idx;

  uinta tbs_cert_end = 0;
  code = parse_data_element(raw_cert, DER_SEQUENCE, idx, cert_end, &tbs_cert_end);
  if (code != OK) {
    return code;
  }

  ret_fields->signed_data_end = tbs_cert_end;

  /*version         [0]  EXPLICIT Version DEFAULT v1*/
  uinta explicit_end = 0;
  code = parse_data_element(raw_cert, DER_EXPLICIT_0, idx, tbs_cert_end, &explicit_end);
  if (code != OK) {
    return code;
  }

  uinta version_end = 0;
  code = parse_data_element(raw_cert, DER_INTEGER, idx, explicit_end, &version_end);
  if (code != OK) {
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
  code = parse_data_element(raw_cert, DER_INTEGER, idx, tbs_cert_end, &serial_end);
  if (code != OK) {
    return code;
  }

  // Currently we do not record the serial number of the cert. There is no current plan to use it.
  *idx = serial_end;

  /*signature            AlgorithmIdentifier*/
  code = parse_alg_id(raw_cert, idx, tbs_cert_end, &ret_fields->sig_id_start, &ret_fields->sig_id_end,
                      &ret_fields->sig_oid_start, &ret_fields->sig_oid_end);
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
  code = parse_time(raw_cert, idx, validity_end, &ret_fields->not_before);
  if (code != OK) {
    return code;
  }

  /*notAfter       Time*/
  code = parse_time(raw_cert, idx, validity_end, &ret_fields->not_after);
  if (code != OK) {
    return code;
  }
  if (*idx != validity_end) {
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
  code = parse_alg_id(raw_cert, idx, public_key_info_end, &ret_fields->pub_key_id_start,
                      &ret_fields->pub_key_id_end, &ret_fields->pub_key_oid_start, &ret_fields->pub_key_oid_end);
  if (code != OK) {
    return code;
  }

  /*subjectPublicKey     BIT STRING*/
  code = parse_bitstring_no_unused(raw_cert, idx, public_key_info_end,
                                   &ret_fields->pub_key_end);
  if (code != OK) {
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
  if (code != OK) {
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
  if (code != OK) {
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
  if (code != OK) {
    return code;
  }

  // Assign default values to be overwritten.
  ret_fields->skid_start = IDX_NONE;
  ret_fields->skid_end = IDX_NONE;
  ret_fields->akid_start = IDX_NONE;
  ret_fields->akid_end = IDX_NONE;
  ret_fields->key_cert_sign = false;
  // ret_fields->path_len_constraint = 0;

  if (explicit_3_end != IDX_NONE) {
    /*Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension*/
    uinta extensions_end = 0;
    code = parse_data_element(raw_cert, DER_SEQUENCE, idx, explicit_3_end, &extensions_end);
    if (code != OK) {
      return code;
    }
    if (extensions_end != explicit_3_end) {
      return TRAILING_DATA;
    }

    byte *extn_oids[MAX_EXTN] = {0};
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
      bool critical = false;
      code = parse_default_bool(raw_cert, idx, extension_end, &critical);
      if (code != OK) {
        return code;
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

      byte *extn_oid = &raw_cert[extn_oid_start];
      uinta extn_oid_size = extn_oid_end - extn_oid_start;

      // TODO: Refactor this code to be more extensible.
      // Check if we have already seen this extn oid.
      // Assigning 128-bit hash-based uuids to each oid would be optimal but very complicated.
      // Linear lookup is fine unless MAX_EXTN is increased by an order of magnitude.
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
          if (code != OK) {
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
  if (code != OK) {
    return code;
  }
  if (ret_fields->sig_end != cert_end) {
    return TRAILING_DATA;
  }

  ret_fields->sig_start = *idx;
  *idx = ret_fields->sig_end;

  return OK;
}
