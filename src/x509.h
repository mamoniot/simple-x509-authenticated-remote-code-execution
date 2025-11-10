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
/*The digitalSignature bit is asserted when the subject public key
      is used for verifying digital signatures, other than signatures on
      certificates (bit 5) and CRLs (bit 6), such as those used in an
      entity authentication service, a data origin authentication
      service, and/or an integrity service.*/
#define KEY_USAGE_FLAG_SIGN (1 << 7)
/*The nonRepudiation bit is asserted when the subject public key is
      used to verify digital signatures, other than signatures on
      certificates (bit 5) and CRLs (bit 6), used to provide a non-
      repudiation service that protects against the signing entity
      falsely denying some action.  In the case of later conflict, a
      reliable third party may determine the authenticity of the signed
      data.  (Note that recent editions of X.509 have renamed the
      nonRepudiation bit to contentCommitment.)*/
#define KEY_USAGE_FLAG_NONREP (1 << 6)
/*The keyEncipherment bit is asserted when the subject public key is
      used for enciphering private or secret keys, i.e., for key
      transport.  For example, this bit shall be set when an RSA public
      key is to be used for encrypting a symmetric content-decryption
      key or an asymmetric private key.*/
#define KEY_USAGE_FLAG_KEY_ENC (1 << 5)
/*The dataEncipherment bit is asserted when the subject public key
      is used for directly enciphering raw user data without the use of
      an intermediate symmetric cipher.  Note that the use of this bit
      is extremely uncommon; almost all applications use key transport
      or key agreement to establish a symmetric key.*/
#define KEY_USAGE_FLAG_DATA_ENC (1 << 4)
/*The keyAgreement bit is asserted when the subject public key is
      used for key agreement.  For example, when a Diffie-Hellman key is
      to be used for key management, then this bit is set.*/
#define KEY_USAGE_FLAG_KEY_AGREEMENT (1 << 3)
/*The keyCertSign bit is asserted when the subject public key is
      used for verifying signatures on public key certificates.  If the
      keyCertSign bit is asserted, then the cA bit in the basic
      constraints extension (Section 4.2.1.9) MUST also be asserted.*/
#define KEY_USAGE_FLAG_KEY_CERT_SIGN (1 << 2)
/*The cRLSign bit is asserted when the subject public key is used
      for verifying signatures on certificate revocation lists (e.g.,
      CRLs, delta CRLs, or ARLs).*/
#define KEY_USAGE_FLAG_KEY_CRL_SIGN (1 << 1)
/*The meaning of the encipherOnly bit is undefined in the absence of
      the keyAgreement bit.  When the encipherOnly bit is asserted and
      the keyAgreement bit is also set, the subject public key may be
      used only for enciphering data while performing key agreement.*/
#define KEY_USAGE_FLAG_KEY_ENC_ONLY (1 << 0)
/*The meaning of the decipherOnly bit is undefined in the absence of
      the keyAgreement bit.  When the decipherOnly bit is asserted and
      the keyAgreement bit is also set, the subject public key may be
      used only for deciphering data while performing key agreement.*/
#define KEY_USAGE_FLAG_KEY_DEC_ONLY (1 << 15)
/*
   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement

   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement

   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature

   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)

   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation*/
#define KEY_USAGE_FLAG_ANY_EXTENDED (1 << 16)
/*id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement*/
#define KEY_USAGE_FLAG_SERVER_AUTH (1 << 17)
/*id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement*/
#define KEY_USAGE_FLAG_CLIENT_AUTH (1 << 18)
/*id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature*/
#define KEY_USAGE_FLAG_CODE_SIGNING (1 << 19)
/*id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)*/
#define KEY_USAGE_FLAG_EMAIL_PROTECT (1 << 20)
/*id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation*/
#define KEY_USAGE_FLAG_TIMESTAMP (1 << 21)
/*id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation*/
#define KEY_USAGE_FLAG_OCSP_SIGN (1 << 22)

// Struct that contains indices to individual fields of an x509 certificate.
// The function parse_x509 will fill out this structure based on the x509 certificate it was passed.
// When using this struct, some familiarity with rfc5280 is expected.
//
// Members with the suffix _start indicate that they are the index of the first byte of their field.
// Members with the suffix _end indicate that they are the index of the byte after the last byte of
// their field. So &raw_cert[sig_start] would point to the first byte of the certificate's
// signature, and sig_end - sig_start is the size in bytes of that signature.
//
// Some members are marked as optional. Only in those cases they may have a value of IDX_NONE, which
// indicates that the original certificate did not contain the field associated with this member.
// All indices not equal to IDX_NONE are guaranteed to be within the bounds of the certificate
// passed to parse_x509.
//
// start-end index semantics were used because they massively simplify parsing and they avoid the
// ambiguity and risk that raw pointer members would pose if they were written to a return structure
// like this. It is very clear that this structure contains only numbers, and as such has no
// lifetime requirements nor handling rules associated with the memory of the original ceriticate.
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

  // Optional, will equal IDX_NONE if empty.
  uinta cert_serial_start;
  uinta cert_serial_end;

  // Optional, will equal IDX_NONE if empty.
  uinta skid_start;
  uinta skid_end;

  // Optional, will equal IDX_NONE if empty.
  uinta akid_start;
  uinta akid_end;

  // Must be present. Contains the not_before field of the certificate, converted to a unix timestamp.
  time_t not_before;
  // Must be present. Contains the not_before field of the certificate, converted to a unix
  // timestamp. This will be a very large timestamp (usually 99991231235959Z) if this certificate has
  // no definite expiration.
  time_t not_after;

  // Will be true if and only if the certificate had the basic constraint extension and that
  // extension contained CA:TRUE. This field must be true if this certificate's public key is
  // allowed to sign certificates.
  bool key_cert_sign;
  // This will be assigned -1 (aka the maximum value of a uint32) if path len was not specified in
  // the basic constraint extension. This will be assigned 0 if key_cert_sign is false.
  uint32 path_len_constraint;

  // Will be true if and only if the certificate had the key usage extension.
  bool has_key_usage;
  // Will be true if and only if the certificate had the extended key usage extension.
  bool has_ext_key_usage;
  // A set of bit flags that summarize the contents of both the key usage and extended key usage
  // extensions of x509. Bitwise operations may be used to extract valid usages for the key
  // specified. If the key usage or extended key usage extensions are missing, their associated
  // flags on this field will be set to 0. To check whether or not the key usage or extended key
  // usage extensions where present on the certificate has_key_usage or has_ext_key_usage should be
  // used instead.
  uint32 key_usage_flags;
} x509Fields;

// Status code for attempting to parse a x509 certificate.
// PARSE_OK is the only "success" code, all others are errors.
typedef enum {
  PARSE_OK,
  UNEXPECTED_END_OF_DATA,
  UNEXPECTED_IDENTIFIER,
  INVALID_LENGTH_FORM,
  TRAILING_DATA,
  INVALID_VERSION,
  INVALID_BOOLEAN,
  INVALID_INTEGER,
  INVALID_BITSTRING,
  INVALID_VALIDITY_TIME,
  MISMATCHED_SIG_ID,
  EXCEEDS_MAX_EXTNS,
  DUPLICATE_EXTNS,
  UNRECOGNIZED_CRITICAL_EXTN,
  INVALID_CRITICALITY,
} ParseCode;

// Parse the x509 contained in raw_cert and raw_cert_size in full. The return value will be PARSE_OK
// on success, or some other error code on failure.
//
// ret_fields will be overwritten and fully initialized with the parsed contents of the certificate
// if this function returns PARSE_OK. The contents of ret_fields are undefined and liable to change
// for any other return value.
ParseCode parse_x509(const byte *raw_cert, uinta raw_cert_size, x509Fields *ret_fields);

// Parse an individual data element of an ASN.1 encoded object. raw_asn1 must point to an ans1
// encoding that is at least parent_end bytes long. This function will look for a field of type
// expected_identifier at byte raw_asn1[*idx].
//
// If PARSE_OK is returned, idx will be incremented to point at the begining of the contents of
// the chosen data field, and ret_content_end will be overwritten with the index of the end of such
// content. So raw_asn1[*ret_content_end] will either be the start of the next field or a buffer
// overflow. The contents of idx and ret_content_end are undefined and liable to change for any
// other return value.
//
// Ensures that *idx <= *ret_content_end <= parent_end after returning PARSE_OK.
ParseCode parse_data_element(const byte *raw_asn1, uint8 expected_identifier, uinta *idx,
                             uinta parent_end, uinta *ret_content_end);
// This function follows the similar semantics to parse_data_element.
//
// Parse the null value of an ASN.1 encoded object. If PARSE_OK is returned, idx will be incremented
// to point at the end of the null value. So raw_asn1[*idx] will either be the start of the next
// field or a buffer overflow.
ParseCode parse_null(const byte *raw_asn1, uinta *idx, uinta parent_end);

#endif
