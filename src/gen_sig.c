#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

#include "stdbool.h"

// This code was written rather quickly and lazily. It is not particularly robust, but I am not
// concerned about this since it is only meant to be used for testing.
int main(int argc, char *argv[]) {
  if (argc < 3) {
    perror("Not enough arguments");
    return -1;
  }

  const char *key_path = argv[1];
  const char *in_path = argv[2];

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  FILE *key_file = fopen(key_path, "r");
  if (key_file == NULL) {
    perror("Error opening key file");
    return -1;
  }

  EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
  if (pkey == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  const char *mdname = NULL;
  if (argc > 3) {
    mdname = argv[3];
  }

  if (EVP_DigestSignInit_ex(mdctx, NULL, mdname, NULL, NULL, pkey, NULL) != 1) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  FILE *in = fopen(in_path, "rb");
  if (in == NULL) {
    perror("Error opening input file");
    return -1;
  }

  void *data = malloc(1 << 18);
  size_t data_cap = 1 << 18;
  size_t data_size = 0;

  while (true) {
    size_t ret = fread(&data[data_size], 1, data_cap - data_size, in);
    if (ret < 0) {
      perror("Error reading input file");
      return -1;
    } else if (ret > 0) {
      data_size += ret;
      if (data_size >= data_cap) {
        data_cap *= 2;
        data = realloc(data, data_cap);
      }
    } else {
      break;
    }
  }

  unsigned char sig[1 << 18];
  size_t sig_size = 1 << 18;

  if (EVP_DigestSign(mdctx, sig, &sig_size, data, data_size) != 1) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  size_t write_start = 0;
  while (write_start < sig_size) {
    size_t ret = write(STDOUT_FILENO, &sig[write_start], sig_size - write_start);
    if (ret < 0) {
      perror("Error writing to stdout");
      return -1;
    } else if (ret > 0) {
      write_start += ret;
    } else {
      break;
    }
  }
  if (write(STDOUT_FILENO, "\n", 1) < 1) {
    perror("Error writing to stdout");
    return -1;
  }
  write_start = 0;
  while (write_start < data_size) {
    size_t ret = write(STDOUT_FILENO, &data[write_start], data_size - write_start);
    if (ret < 0) {
      perror("Error writing to stdout");
      return -1;
    } else if (ret > 0) {
      write_start += ret;
    } else {
      break;
    }
  }

  return EXIT_SUCCESS;
}
