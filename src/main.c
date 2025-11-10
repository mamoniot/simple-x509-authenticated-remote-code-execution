#include "assert.h"
#include "errno.h"
#include "fcntl.h"
#include "netinet/in.h"
#include "stdio.h"
#include "sys/mman.h"
#include "sys/socket.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "time.h"
#include "unistd.h"
#include "dirent.h"

#include "x509.h"
#include "crypto.h"
#include "basic.h"
#include <string.h>

const int TCP_BACKLOG = 16;
const uint16 DEFAULT_PORT = 56544;
const uinta MAX_SCRIPT_SIZE = 2 * GIGABYTE;
const uinta TCP_RECV_TIMEOUT_SECS = 5;
const uinta TCP_MAX_TIMEOUT_SECS = 60;

// Execture the bash script contained in script and script_size in a new process with shared stdout.
void exec_script(byte *script, uinta script_size, uint32 script_n) {
  int in_pipe[2] = {0};
  if (pipe(in_pipe) < 0) {
    fprintf(stderr, "Failed to create a pipe for executing remote bash script #%d\n", script_n);
    return;
  }

  pid_t pid = fork();
  if (pid < 0) {
    fprintf(stderr, "Failed to create a child process for remote bash script #%d\n", script_n);
    close(in_pipe[0]);
    close(in_pipe[1]);
    return;
  }

  // Past this point we assume execution was successful. The following system calls should rarely
  // fail and it doesn't really matter if they do fail.
  if (pid == 0) {
    // This is the child process.
    // Redirect stdin.
    dup2(in_pipe[0], STDIN_FILENO);
    close(in_pipe[0]);
    close(in_pipe[1]);

    const char* BASH = "bash";
    execlp(BASH, BASH, NULL);
    // execlp only returns on error.
    perror("execlp");
    exit(-1);
  }

  // We have to flush stdout for it to consistently appear before the script output.
  printf("Remote bash script #%d received and authenticated, executing now...\n", script_n);
  fflush(stdout);

  // This write could deadlock if we ran a command other than bash.
  write(in_pipe[1], script, script_size);

  close(in_pipe[0]);
  close(in_pipe[1]);

  waitpid(pid, NULL, 0);
}

// ret_pub_key will be overwritten with a new public key if this function returns true. The
// contents of ret_pub_key are undefined and liable to change for any other return value.
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
      fprintf(stderr, "Cerficate has restricted usage, it must explicitly allow code signing and "
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

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "%s: Missing file or directory of trusted x509 certificates\n", argv[0]);
    return -1;
  }
  char *path = argv[1];

  struct stat path_stat = {0};
  if (stat(path, &path_stat) != 0) {
    fprintf(stderr, "Unable to retrieve file stats of %s; does it exist?\n", path);
    return -1;
  }

  // We store each of the keys in a dynamic array, but that dynamic array starts with memory backed
  // by the stack to avoid allocation in the common case of one key.
  PubKey one_key = {0};
  PubKey *keys = &one_key;
  uinta attempts_total = 0;
  uinta keys_size = 0;
  uinta keys_cap = 1;

  if (S_ISDIR(path_stat.st_mode)) {
    // The given path is a directory, we will attempt to trust every valid certificate found within it.
    DIR *dir = opendir(path);
    if (dir == NULL) {
      fprintf(stderr, "Could not open certificate directory '%s'\n", path);
      return - 1;
    }

    uinta full_file_path_cap = KILOBYTE;
    char *full_file_path = malloc(KILOBYTE);
    uinta path_len = strlen(path);
    assert(path_len > 1);
    bool has_sep = path[path_len - 1] == '/';

    while (true) {
      struct dirent *entry = readdir(dir);
      if (entry == NULL) {
        break;
      }
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }

      if (keys_size >= keys_cap) {
        if (keys_cap == 1) {
          keys_cap = 8;
          keys = malloct(PubKey, 8);
          // Copy over key and zeroize it for safety.
          *keys = one_key;
          memzrot(&one_key, 1);
        } else {
          keys_cap *= 2;
          keys = realloct(PubKey, keys, keys_cap);
        }
      }

      // This is not a very efficient or portable way to concatenate file paths, but the correct
      // version is time consuming to write. This is good enough.
      uinta total_size = path_len + 1 + strlen(entry->d_name) + 1;
      if (total_size > full_file_path_cap) {
        full_file_path_cap = total_size;
        full_file_path = realloc(full_file_path, total_size);
      }
      if (has_sep) {
        sprintf(full_file_path, "%s%s", path, entry->d_name);
      } else {
        sprintf(full_file_path, "%s/%s", path, entry->d_name);
      }

      assert(keys_size < keys_cap);
      attempts_total += 1;
      if (read_cert(full_file_path, &keys[keys_size])) {
        keys_size += 1;
      }
    }

    closedir(dir);

    if (keys_size == 0) {
      fprintf(stderr, "Could not find a valid certificate in '%s'\n", path);
      return -1;
    }
    if (attempts_total != keys_size) {
      printf("Found %d files in '%s' but only %d were valid x509 certificates; proceeding with just the valid certificates\n", cast(uint32, attempts_total), path, cast(uint32, keys_size));
    }
  } else {
    // The given path is a file, parse it as a single trusted certificate.
    if (read_cert(path, &keys[0])) {
      keys_size += 1;
    } else {
      return -1;
    }
  }

  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    fprintf(stderr, "Failed to open a TCP socket\n");
    return -1;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(DEFAULT_PORT);
  struct timeval tv = {0};
  tv.tv_sec = TCP_RECV_TIMEOUT_SECS;
  tv.tv_usec = 0;

  // TODO: support concurrency properly since anything lesser will have DDOS problems.
  // // Set a timeout so that recv is much less of a DDOS vector.
  // if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, cast(const char *, &tv), sizeof(tv)) < 0) {
  //   printf("Could not assign a recv timeout to tcp socket\n");
  //   // We do not consider this fatal.
  // }

  if (bind(sock_fd, cast(struct sockaddr *, &server_addr), sizeof(server_addr)) < 0) {
    close(sock_fd);
    fprintf(stderr, "Failed to bind a TCP socket to port %d\n", DEFAULT_PORT);
    return -1;
  }
  if (listen(sock_fd, TCP_BACKLOG) < 0) {
    close(sock_fd);
    fprintf(stderr, "Failed to listen for TCP connections\n");
    return -1;
  }

  byte *buf = malloc(KILOBYTE);
  uinta buf_cap = KILOBYTE;
  uint32 script_n = 0;

  while (true) {
    struct sockaddr_in clien_addr = {0};
    socklen_t clien_addr_size = sizeof(clien_addr);
    int conn_fd =
        accept(sock_fd, cast(struct sockaddr *, &clien_addr), &clien_addr_size);
    if (conn_fd < 0) {
      fprintf(stderr, "Failed to accept a TCP connection, retrying...\n");
      continue;
    }

    uinta buf_size = 0;
    bool retry = true;
    clock_t start_time = clock();

    while (true) {
      assert(buf_size < buf_cap);
      inta ret = recv(conn_fd, &buf[buf_size], buf_cap - buf_size, 0);
      if (ret < 0) {
        fprintf(stderr, "Failed to receive data from a TCP connection\n");
        break;
      } else if (ret > 0) {
        buf_size += ret;
        if (buf_size >= MAX_SCRIPT_SIZE) {
          fprintf(stderr, "TCP connection exceeded maximum allowed script size of %" PRIu64 "\n",
                 MAX_SCRIPT_SIZE);
          break;
        } else if (buf_size >= buf_cap) {
          buf_cap *= 2;
          buf = realloc(buf, buf_cap);
        }
      } else {
        // Null terminate the buffer for safety. It is not within buf_size and should go unused.
        buf[buf_size] = 0;
        retry = false;
        break;
      }

      clock_t dur = (clock() - start_time)/CLOCKS_PER_SEC;
      if (dur >= TCP_MAX_TIMEOUT_SECS) {
        fprintf(stderr, "TCP connection took %d seconds and was timed-out\n", cast(uint32, dur));
        break;
      }
    }

    close(conn_fd);
    if (retry) {
      continue;
    }

    /*A bash script whose 1st line is the signature of the rest of the bash file.*/
    // A raw public key signature may and often will incidentally contain a newline character. So
    // we need a way to tell apart an incidental newline from the newline separating the signature
    // and the script. One option is to use an encoding scheme for the signature, but this is
    // dangerous as it introduces nonstandard complexity and ambiguity. It would be ideal if we
    // can use a standard format for signatures, but the design specs specifically ask for a
    // custom format with the signature on the first line. Since signatures are
    // fixed-size, we can interpret every input byte less than the signature size as unambiguously
    // part of the signature.
    // Furthermore, if the first line is just a signature, we cannot easily include a key identifier
    // with the script, so we have to try to authenticate with each public key until we find a match.
    // This is safe to do just not very efficient.
    bool is_authentic = false;
    time_t now = time(NULL);

    for(int i = 0; i < keys_size; i += 1) {
      PubKey *pub_key = &keys[i];
      if (now > pub_key->expiry) {
        // This key has expired and should be removed.
        if (keys_size > 1) {
          // Swap remove.
          swap(PubKey, pub_key, &keys[keys_size - 1]);
          keys_size -= 1;
          i -= 1;
          continue;
        } else {
          fprintf(stderr, "All certificates have expired, closing server\n");
          return -1;
        }
      }

      uinta sig_end = pub_key->exp_sig_size;
      uinta script_start = pub_key->exp_sig_size + 1;
      if (script_start <= buf_size && buf[sig_end] == '\n') {
        byte *script = &buf[script_start];
        uinta script_size = buf_size - script_start;
        if (pub_key_verify(pub_key, script, script_size, buf, sig_end)) {
          // The signature is valid, so execute the script.
          is_authentic = true;
          script_n += 1;
          exec_script(script, script_size, script_n);
          break;
        }
      }
    }
    if (!is_authentic) {
      fprintf(stderr, "Remote bash script could not be authenticated, aborting execution\n");
    }
  }

  close(sock_fd);

  return 0;
}
