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

  bool has_key_usage;
  bool has_ext_key_usage;
  uint32 key_usage_flags;
} x509Fields;

typedef enum {
  OK,
  UNEXPECTED_END_OF_DATA,
  UNEXPECTED_IDENTIFIER,
  INVALID_LENGTH_FORM,
  TRAILING_DATA,
  INVALID_VERSION,
  INVALID_BOOLEAN,
  INVALID_BITSTRING,
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
