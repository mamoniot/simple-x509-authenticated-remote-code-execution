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
#include <wchar.h>

const int TCP_BACKLOG = 16;
const uint16 TCP_PORT = 59261;

void exec_script(byte *script, uinta script_size) {
  int in_pipe[2] = {0};
  if (pipe(in_pipe) < 0) {
    printf("TODO");
    return;
  }

  pid_t pid = fork();
  if (pid < 0) {
    printf("TODO");
    return;
  }

  // Past this point we assume execution was successful. The following system calls should never fail.
  if (pid == 0) {
    // This is the child process.
    // Redirect stdin.
    dup2(in_pipe[0], STDIN_FILENO);
    close(in_pipe[0]);
    close(in_pipe[1]);

    exit(execvp("/bin/bash", NULL));
  }

  printf("TODO Success");
  write(in_pipe[1], script, script_size);

  close(in_pipe[0]);
  close(in_pipe[1]);

  waitpid(pid, NULL, 0);
}

int main(int argc, char *argv[]) {
  if (argc <= 2) {
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

  munmap(raw_cert, raw_cert_size);
  close(fd);

  if (is_pub_key_populated) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
      printf("TODO");
      return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = TCP_PORT;

    if (bind(sock_fd, cast(struct sockaddr *, &server_addr), sizeof(server_addr)) < 0) {
      close(sock_fd);
      printf("TODO");
      return -1;
    }
    if (listen(sock_fd, TCP_BACKLOG) < 0) {
      close(sock_fd);
      printf("TODO");
      return -1;
    }

    byte *buf = malloc(KILOBYTE);
    uinta buf_cap = KILOBYTE;

    while (true) {
      struct sockaddr_in clien_addr;
      socklen_t clien_addr_size = sizeof(clien_addr);
      int conn_fd =
          accept(sock_fd, cast(struct sockaddr *, &clien_addr), &clien_addr_size);
      if (conn_fd < 0) {
        if (errno == EINTR) {
          continue;
        }
        printf("TODO");
        break;
      }

      uinta buf_size = 0;
      while (true) {
        inta ret = recv(conn_fd, &buf[buf_size], buf_cap - buf_size, MSG_TRUNC);
        if (ret < 0) {
          close(sock_fd);
          close(conn_fd);
          printf("TODO");
          return -1;
        } else if (ret == 0) {
          // Null terminate the buffer for later.
          assert(buf_size < buf_cap);
          buf[buf_size] = 0;
          buf_size += 1;
          break;
        } else {
          buf_size += ret;
          if (buf_size == buf_cap) {
            // NOTE: In a production environment this growth should be capped and OOM checked.
            buf_cap *= 2;
            buf = realloc(buf, buf_cap);
          }
        }
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
      uinta script_end = buf_size - 1;
      if (script_start < script_end && buf[sig_end] == '\n') {
        // The script is null terminated, but the null terminator is not included in the size.
        byte *script = &buf[script_start];
        uinta script_size = script_end - script_start;
        if (pub_key_verify(&pub_key, script, script_size, buf, sig_end)) {
          // The signature is valid, so execute the script.
          exec_script(script, script_size);
        } else {
          printf("TODO");
        }
      } else if (script_start == script_end) {
        printf("TODO");
      } else {
        printf("TODO");
      }
    }

    close(sock_fd);
  }

  return 0;
}
