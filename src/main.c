#include "errno.h"
#include "fcntl.h"
#include "stdio.h"
#include "sys/mman.h"
#include "sys/socket.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "unistd.h"
#include "netinet/in.h"
#include "assert.h"
#include "time.h"

#include "x509.h"
#include "crypto.h"
#include "basic.h"

const int TCP_BACKLOG = 16;
const uint16 DEFAULT_PORT = 56544;
const uinta MAX_SCRIPT_SIZE = 2 * GIGABYTE;

void exec_script(byte *script, uinta script_size) {
  int in_pipe[2] = {0};
  if (pipe(in_pipe) < 0) {
    printf("Failed to create a pipe for executing the remote bash script\n");
    return;
  }

  pid_t pid = fork();
  if (pid < 0) {
    printf("Failed to create a child process for the remote bash script\n");
    return;
  }

  // Past this point we assume execution was successful. The following system calls should never fail.
  if (pid == 0) {
    // This is the child process.
    // Redirect stdin.
    dup2(in_pipe[0], STDIN_FILENO);
    close(in_pipe[1]);

    printf("Remote bash script received and authenticated, executing now...\n");
    const char* BASH = "bash";
    int ret = execlp(BASH, BASH, NULL);
    fflush(stdout);
    exit(ret);
  }

  write(in_pipe[1], script, script_size);

  close(in_pipe[0]);
  close(in_pipe[1]);

  waitpid(pid, NULL, 0);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("%s: Missing file operand\n", argv[0]);
    return -1;
  }
  char *path = argv[1];

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("Unable to open input file: %s\n", path);
    return -1;
  }

	struct stat st;
  int code = fstat(fd, &st);
  if (code < 0) {
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
    switch (extract_self_sign_for_code_sign(raw_cert, &fields, time(NULL), &pub_key)) {
    case CERT_OK:
      is_pub_key_populated = true;
      break;
    case EXPIRED:
      printf("This cerficate has expired\n");
      break;
    case INVALID_SELF_SIGN:
      printf("This cerficate is not self-signed\n");
      break;
    case INVALID_USAGE:
      printf("This cerficate has restricted usage, it must explicitly allow code signing and certificate signing\n");
      break;
    case INVALID_PUB_KEY_PARAMS:
      printf("This cerficate has invalid public key parameters\n");
      break;
    case INVALID_PUB_KEY:
      printf("This cerficate had an invalid public key\n");
      break;
    case UNSUPPORTED_ALG:
      printf("This cerficate uses an unsupported public key algorithm\n");
      break;
    case INVALID_SIG:
      printf("This cerficate's signature could not be authenticated\n");
      break;
    }
    break;
  case UNEXPECTED_END_OF_DATA:
    printf("Certificate sequence encoding ended unexpectedly\n");
    break;
  case UNEXPECTED_IDENTIFIER:
    printf("Encountered unexpected identifier in certificate\n");
    break;
  case INVALID_LENGTH_FORM:
    printf("Encountered invalid encoding length in certificate\n");
    break;
  case TRAILING_DATA:
    printf("Certificate encoding had invalid trailing data\n");
    break;
  case INVALID_VERSION:
    printf("Only v3 x509 certificates are accepted\n");
    break;
  case INVALID_BOOLEAN:
    printf("Encountered invalid boolean value in certificate\n");
    break;
  case INVALID_VALIDITY_TIME:
    printf("Encountered invalid certificate validity timestamp\n");
    break;
  case MISMATCHED_SIG_ID:
    printf("Certificate signature identifiers did not match\n");
    break;
  case EXCEEDS_MAX_EXTNS:
    printf("Certificate contained too many extensions\n");
    break;
  case DUPLICATE_EXTNS:
    printf("Certificate contained a duplicate extension\n");
    break;
  case UNRECOGNIZED_CRITICAL_EXTN:
    printf("Certificate contained an unrecognized critical extension\n");
    break;
  case INVALID_CRITICALITY:
    printf("Certificate extension had incorrect criticality\n");
    break;
  case INVALID_BITSTRING:
    printf("Encountered invalid bitstring in certificate\n");
    break;
  }

  munmap(raw_cert, raw_cert_size);
  close(fd);

  if (!is_pub_key_populated) {
    return -1;
  }

  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    printf("Failed to open a TCP socket\n");
    return -1;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(DEFAULT_PORT);

  if (bind(sock_fd, cast(struct sockaddr *, &server_addr), sizeof(server_addr)) < 0) {
    close(sock_fd);
    printf("Failed to bind a TCP socket to port %d\n", DEFAULT_PORT);
    return -1;
  }
  if (listen(sock_fd, TCP_BACKLOG) < 0) {
    close(sock_fd);
    printf("Failed to listen for TCP connections\n");
    return -1;
  }

  byte *buf = malloc(KILOBYTE);
  uinta buf_cap = KILOBYTE;

  while (true) {
    struct sockaddr_in clien_addr = {0};
    socklen_t clien_addr_size = sizeof(clien_addr);
    int conn_fd =
        accept(sock_fd, cast(struct sockaddr *, &clien_addr), &clien_addr_size);
    if (conn_fd < 0) {
      printf("Failed to accept a TCP connection, retrying...\n");
      continue;
    }

    uinta buf_size = 0;
    while (true) {
      assert(buf_size < buf_cap);
      inta ret = recv(conn_fd, &buf[buf_size], buf_cap - buf_size, 0);
      if (ret < 0) {
        close(sock_fd);
        close(conn_fd);
        printf("Failed to receive data from a TCP connection\n");
        return -1;
      } else if (ret > 0) {
        buf_size += ret;
        if (buf_size >= MAX_SCRIPT_SIZE) {
          printf("TCP connection exceeded maximum allowed script size of %" PRIu64 "\n",
                 MAX_SCRIPT_SIZE);
          break;
        } else if (buf_size >= buf_cap) {
          // NOTE: In a production environment this growth should be capped and OOM checked.
          buf_cap *= 2;
          buf = realloc(buf, buf_cap);
        }
      } else {
        // Null terminate the buffer for safety. It is not within buf_size and should go unused.
        buf[buf_size] = 0;
        break;
      }
    }
    close(conn_fd);

    if (buf_size >= MAX_SCRIPT_SIZE) {
      continue;
    }

    /*A bash script whose 1st line is the signature of the rest of the bash file.*/
    // A raw public key signature may and often will incidentally contain a newline character. So
    // we need a way to tell apart an incidental newline from the newline separating the signature
    // and the script. One option is to use an encoding scheme for the signature, but this is
    // dangerous as it introduces nonstandard complexity and ambiguity. Instead, since
    // signatures are fixed-size, we can interpret every input byte less than the signature size
    // as unambiguously part of the signature.
    uinta sig_end = pub_key.exp_sig_size;
    uinta script_start = pub_key.exp_sig_size + 1;
    if (script_start <= buf_size && buf[sig_end] == '\n') {
      byte *script = &buf[script_start];
      uinta script_size = buf_size - script_start;
      if (pub_key_verify(&pub_key, script, script_size, buf, sig_end)) {
        // The signature is valid, so execute the script.
        exec_script(script, script_size);
      } else {
        printf("Remote bash script could not be authenticated, aborting execution\n");
      }
    } else {
      printf("Remote bash script did not contain a signature, aborting execution\n");
    }
  }

  close(sock_fd);

  return 0;
}
