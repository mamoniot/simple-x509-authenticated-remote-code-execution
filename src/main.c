#include "fcntl.h"
#include "stdio.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "unistd.h"
#include "errno.h"

#include "x509.h"
#include "crypto.h"
#include "basic.h"
#include <time.h>


int main(int argc, char *argv[]) {
  if (argc <= 2) {
    printf("%s: Missing file operand\n", argv[0]);
    return -1;
  }
  char *path = argv[1];

  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    printf("Unable to open input file: %s\n", path);
    return -1;
  }

	struct stat st;
  int code = fstat(fd, &st);
  if (code != 0) {
    printf("fstat on file %s falied with err %d\n", path, code);
    close(fd);
    return -1;
  }
  uinta raw_cert_size = st.st_size;

  byte *raw_cert = mmap(0, raw_cert_size, PROT_READ, MAP_SHARED, fd, 0);
  if (raw_cert == MAP_FAILED) {
    printf("mmap failed with errno = %d\n", errno);
    close(fd);
    return -1;
  }

  bool is_pub_key_populated = false;
  PubKey pub_key = {0};
  x509Fields fields = {0};
  switch (parse_x509(raw_cert, raw_cert_size, &fields)) {
  case OK:
    if (extract_self_sign(raw_cert, &fields, time(NULL), &pub_key)) {
      is_pub_key_populated = true;
    } else {
      printf("The cerficate had an invalid signature");
    }
    break;
  case UNEXPECTED_END_OF_DATA:
    printf("TODO");
    break;
  case UNEXPECTED_IDENTIFIER:
    printf("TODO");
    break;
  case INVALID_END_OF_DATA:
    printf("TODO");
    break;
  case INVALID_LENGTH_FORM:
    printf("TODO");
    break;
  case INVALID_LENGTH_TOO_LONG:
    printf("TODO");
    break;
  case TRAILING_DATA:
    printf("TODO");
    break;
  case INVALID_VERSION:
    printf("TODO");
    break;
  case INVALID_BOOLEAN:
    printf("TODO");
    break;
  case INVALID_VALIDITY_TIME:
    printf("TODO");
    break;
  case MISMATCHED_SIG_ID:
    printf("TODO");
    break;
  case UNKNOWN_SIG_ID:
    printf("TODO");
    break;
  case INVALID_SIG_PARAMS:
    printf("TODO");
    break;
  case EXCEEDS_MAX_EXTNS:
    printf("TODO");
    break;
  case DUPLICATE_EXTNS:
    printf("TODO");
    break;
  case UNRECOGNIZED_CRITICAL_EXTN:
    printf("TODO");
    break;
  case EXPLICIT_DEFAULT:
    printf("TODO");
    break;
  }

  int ret = munmap(raw_cert, raw_cert_size);
  close(fd);

  if (is_pub_key_populated) {
    
  }

  return ret;
}
