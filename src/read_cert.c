#include "assert.h"
#include "errno.h"
#include "fcntl.h"
#include "stdio.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "time.h"
#include "unistd.h"

#include "basic.h"
#include "crypto.h"
#include "x509.h"

bool read_cert(const char *path, PubKey *ret_pub_key) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Unable to open input file: '%s'\n", path);
    return false;
  }

  struct stat st;
  int code = fstat(fd, &st);
  if (code < 0) {
    fprintf(stderr, "fstat on file '%s' failed with err %d\n", path, code);
    close(fd);
    return false;
  }
  inta raw_cert_size = st.st_size;

  if (raw_cert_size <= 0) {
    fprintf(stderr, "'%s' does not contain data\n", path);
    close(fd);
    return false;
  }

  // mmap the file so we don't have to allocate and copy its contents.
  byte *raw_cert = mmap(0, raw_cert_size, PROT_READ, MAP_SHARED, fd, 0);
  if (raw_cert == MAP_FAILED) {
    if (errno == ENODEV) {
      fprintf(stderr, "'%s' is not a file\n", path);
    } else {
      fprintf(stderr, "mmap of '%s' failed with errno = %d\n", path, errno);
    }
    close(fd);
    return false;
  }

  // Parse and subsequently verify the certificate.
  bool is_pub_key_populated = false;
  x509Fields fields = {0};
  switch (parse_x509(raw_cert, raw_cert_size, &fields)) {
  case PARSE_OK:
    switch (extract_self_sign_for_code_sign(raw_cert, &fields, time(NULL), ret_pub_key)) {
    case CERT_OK:
      is_pub_key_populated = true;
      break;
    case EXPIRED:
      fprintf(stderr, "Cerficate has expired (%s)\n", path);
      break;
    case NOT_BEFORE:
      fprintf(stderr, "Cerficate is dated into the future (%s)\n", path);
      break;
    case INVALID_SELF_SIGN:
      fprintf(stderr, "Cerficate is not self-signed (%s)\n", path);
      break;
    case INVALID_USAGE:
      fprintf(stderr,
              "Cerficate has restricted usage, it must explicitly allow code signing and "
              "certificate signing (%s)\n",
              path);
      break;
    case INVALID_PUB_KEY_PARAMS:
      fprintf(stderr, "Cerficate has invalid public key parameters (%s)\n", path);
      break;
    case INVALID_PUB_KEY:
      fprintf(stderr, "Cerficate had an invalid public key (%s)\n", path);
      break;
    case UNSUPPORTED_ALG:
      fprintf(stderr, "Cerficate uses an unsupported public key algorithm (%s)\n", path);
      break;
    case INVALID_SIG:
      fprintf(stderr, "Cerficate's signature could not be authenticated (%s)\n", path);
      break;
    }
    break;
  case UNEXPECTED_END_OF_DATA:
    fprintf(stderr, "Certificate sequence encoding ended unexpectedly (%s)\n", path);
    break;
  case UNEXPECTED_IDENTIFIER:
    fprintf(stderr, "Encountered unexpected identifier in certificate (%s)\n", path);
    break;
  case INVALID_LENGTH_FORM:
    fprintf(stderr, "Encountered invalid encoding length in certificate (%s)\n", path);
    break;
  case TRAILING_DATA:
    fprintf(stderr, "Certificate encoding had invalid trailing data (%s)\n", path);
    break;
  case INVALID_VERSION:
    fprintf(stderr, "Only v3 x509 certificates are accepted (%s)\n", path);
    break;
  case INVALID_BOOLEAN:
    fprintf(stderr, "Encountered invalid boolean value in certificate (%s)\n", path);
    break;
  case INVALID_INTEGER:
    fprintf(stderr, "Encountered invalid integer value in certificate (%s)\n", path);
    break;
  case INVALID_VALIDITY_TIME:
    fprintf(stderr, "Encountered invalid certificate validity timestamp (%s)\n", path);
    break;
  case MISMATCHED_SIG_ID:
    fprintf(stderr, "Certificate signature identifiers did not match (%s)\n", path);
    break;
  case EXCEEDS_MAX_EXTNS:
    fprintf(stderr, "Certificate contained too many extensions (%s)\n", path);
    break;
  case DUPLICATE_EXTNS:
    fprintf(stderr, "Certificate contained a duplicate extension (%s)\n", path);
    break;
  case UNRECOGNIZED_CRITICAL_EXTN:
    fprintf(stderr, "Certificate contained an unrecognized critical extension (%s)\n", path);
    break;
  case INVALID_CRITICALITY:
    fprintf(stderr, "Certificate extension had incorrect criticality (%s)\n", path);
    break;
  case INVALID_BITSTRING:
    fprintf(stderr, "Encountered invalid bitstring in certificate (%s)\n", path);
    break;
  }

  munmap(raw_cert, raw_cert_size);
  close(fd);
  return is_pub_key_populated;
}
