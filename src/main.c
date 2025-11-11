#include "assert.h"
#include "dirent.h"
#include "errno.h"
#include "fcntl.h"
#include "netinet/in.h"
#include "stdio.h"
#include "string.h"
#include "sys/epoll.h"
#include "sys/mman.h"
#include "sys/socket.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "time.h"
#include "unistd.h"

#include "basic.h"
#include "crypto.h"
#include "x509.h"

// Internal TCP socket session backlog.
const int TCP_BACKLOG = 16;
// Port number to bind to. If I continued development I would add a -p argument so this can be
// configured at runtime.
const uint16 DEFAULT_PORT = 56544;
// Maximum size any script can be before it is rejected.
const uinta MAX_SCRIPT_SIZE = 2 * GIGABYTE;
// Amount of epoll event batching to allow.
#define MAX_EPOLL_EVENTS 8
// The maximum number of concurrent connections this server allows.
#define MAX_CONCURRENCY 128

// Structure that contains a connection file descriptor and a buffer to receive TCP data in.
// The buffer is not freed until program exit, it is reused by new connections.
typedef struct {
  int fd;
  clock_t open_time;
  uinta buf_size;
  uinta buf_cap;
  byte *buf;
} Connection;

// Structure that contains all persistent allocated memory or resources for this program.
// It is safe to initialize it entirely with zeros.
//
// NOTE: In a real-time environment I would store connections on a dynamic min-heap with
// a free list, so that this can scale to thousands of concurrent requests, instead of
// just hundreds. Though it scales worse, a fixed-size array is simple, safe and surprisingly
// efficient.
typedef struct {
  int epoll_fd;
  int sock_fd;
  int script_n;
  PubKey *keys;
  uinta keys_size;
  uinta keys_cap;
  Connection conns[MAX_CONCURRENCY];
  uinta conns_total;
} Resources;

// Free all memory or resources used by the program. In theory it is unnecessary to call this as the
// OS will do this on program exit, but on some systems the OS can fail to do cleanup correctly,
// particularly with sockets bound to ports. It also helps with resource management analysis.
void free_all(Resources *resources) {
  if (resources->epoll_fd > 0) {
    close(resources->epoll_fd);
  }
  if (resources->sock_fd > 0) {
    close(resources->sock_fd);
  }
  if (resources->keys != NULL) {
    for_each_in(PubKey, key, resources->keys, resources->keys_size) { pub_key_free(key); }
    free(resources->keys);
  }
  // This array has no ordering or contiguity guarantees so we must search the entire array.
  for_each_in(Connection, conn, resources->conns, MAX_CONCURRENCY) {
    if (conn->fd > 0) {
      close(conn->fd);
    }
    if (conn->buf != NULL) {
      free(conn->buf);
    }
  }
  // Erase all invalid handles for safety.
  memzrot(resources, 1);
}

// Close an individual connection and clear its input buffer.
// Requires conn to be currently in use with conn->fd > 0.
void free_conn(Resources *resources, Connection *conn) {
  close(conn->fd);
  // We do not free buffers here so that they may be reused.
  // free_all is responsible for freeing connection buffers.
  conn->fd = 0;
  conn->buf_size = 0;
  conn->open_time = 0;
  resources->conns_total -= 1;
}

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
    int ret = dup2(in_pipe[0], STDIN_FILENO);
    close(in_pipe[0]);
    close(in_pipe[1]);
    if (ret < 0) {
      perror("dup2 pipe to stdin failed");
    } else {
      // Execute bash such that it runs whatever the parent process feeds it from in_pipe.
      const char *BASH = "bash";
      execlp(BASH, BASH, NULL);
      // execlp only returns on error.
      perror("execlp");
    }
    exit(-1);
  }

  // We have to flush stdout for it to consistently appear before the script output.
  printf("Remote bash script #%d received and authenticated, executing now...\n", script_n);
  fflush(stdout);

  // This write could deadlock if we ran a command other than bash.
  uinta i = 0;
  while (i < script_size) {
    int ret = write(in_pipe[1], &script[i], script_size - i);
    if (ret < 0) {
      perror("write to command pipe failed");
      break;
    }
    i += ret;
  }

  close(in_pipe[0]);
  // Closing the pipe should flush it according to man.
  close(in_pipe[1]);

  // Wait for the script to finish executing before returning.
  // We could instead choose to run scripts concurrently, but this would make stdout very difficult
  // to manage, and I would wager a user would not want their scripts to run concurrently.
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

int main_protected(Resources *resources, int argc, char *argv[]) {
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

  // We store each of the keys in a dynamic array.
  resources->keys = malloct(PubKey, 4);
  resources->keys_cap = 4;
  uinta attempts_total = 0;

  if (S_ISDIR(path_stat.st_mode)) {
    // The given path is a directory, we will attempt to trust every valid certificate found within
    // it.
    DIR *dir = opendir(path);
    if (dir == NULL) {
      fprintf(stderr, "Could not open certificate directory '%s'\n", path);
      return -1;
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

      if (resources->keys_size >= resources->keys_cap) {
        resources->keys_cap *= 2;
        resources->keys = realloct(PubKey, resources->keys, resources->keys_cap);
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

      attempts_total += 1;
      if (read_cert(full_file_path, &resources->keys[resources->keys_size])) {
        resources->keys_size += 1;
      }
    }

    free(full_file_path);
    closedir(dir);

    if (resources->keys_size == 0) {
      fprintf(stderr, "Could not find a valid certificate in '%s'\n", path);
      return -1;
    }
    if (attempts_total != resources->keys_size) {
      printf("Found %d files in '%s' but only %d were valid x509 certificates; proceeding with "
             "just the valid certificates\n",
             cast(uint32, attempts_total), path, cast(uint32, resources->keys_size));
    }
  } else {
    // The given path is a file, parse it as a single trusted certificate.
    assert(resources->keys_cap > 0);
    if (read_cert(path, &resources->keys[0])) {
      resources->keys_size += 1;
    } else {
      return -1;
    }
  }

  resources->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (resources->sock_fd < 0) {
    perror("Failed to open a TCP socket");
    return -1;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(DEFAULT_PORT);

  if (bind(resources->sock_fd, cast(struct sockaddr *, &server_addr), sizeof(server_addr)) < 0) {
    perror("Failed to bind a TCP socket\n");
    return -1;
  }
  if (listen(resources->sock_fd, TCP_BACKLOG) < 0) {
    perror("Failed to bind a TCP socket\n");
    return -1;
  }

  resources->epoll_fd = epoll_create1(0);
  if (resources->epoll_fd < 0) {
    perror("Call to epoll_create1 failed");
    return -1;
  }

  assert(MAX_CONCURRENCY > 0 && MAX_EPOLL_EVENTS > 2);
  struct epoll_event events[MAX_EPOLL_EVENTS] = {0};

  // MAX_INT32 is a sentinel value that implies a connection is available on sock_fd.
  struct epoll_event add_sock = {
      .events = EPOLLIN,
      .data.fd = MAX_INT32,
  };
  if (epoll_ctl(resources->epoll_fd, EPOLL_CTL_ADD, resources->sock_fd, &add_sock) < 0) {
    perror("Call to epoll_ctl failed");
    return -1;
  }

  while (true) {
    // Block on epoll events as long as necessary.
    int res = epoll_wait(resources->epoll_fd, events, MAX_EPOLL_EVENTS, -1);
    if (res < 0) {
      perror("Call to epoll_wait failed");
      return -1;
    }

    for_each_in(struct epoll_event, event, events, res) {
      int idx = event->data.fd;
      if (idx == MAX_INT32) {
        // Clear old connections if there are too many.
        if (resources->conns_total >= MAX_CONCURRENCY) {
          Connection *min_conn = NULL;
          int64 min_open_time = MAX_INT64;
          // Linear lookup the oldest connection and close it in favor of the new connection.
          for_each_in(Connection, conn, resources->conns, MAX_CONCURRENCY) {
            if (conn->fd > 0 && conn->open_time < min_open_time) {
              min_open_time = conn->open_time;
              min_conn = conn;
            }
          }
          assert(min_conn != NULL);
          free_conn(resources, min_conn);
        }

        // Accept the new connection.
        struct sockaddr_in clien_addr = {0};
        socklen_t clien_addr_size = sizeof(clien_addr);
        int conn_fd =
            accept(resources->sock_fd, cast(struct sockaddr *, &clien_addr), &clien_addr_size);
        if (conn_fd < 0) {
          perror("Failed to accept a TCP connection");
          continue;
        }

        // Search for an unused connection resource and utilize it.
        resources->conns_total += 1;
        // Linear search from the start of the array so that it prefers to reuse buffers rather than
        // making new ones.
        for_each_idx(Connection, i, conn, resources->conns, MAX_CONCURRENCY) {
          if (conn->fd <= 0) {
            // Add connection to epoll.
            struct epoll_event add_conn = {
                .events = EPOLLIN | EPOLLRDHUP,
                // data is recorded as the index into the resources->conns array.
                // This dramatically reduces the complexity of memory management for this callback.
                .data.fd = i,
            };
            if (epoll_ctl(resources->epoll_fd, EPOLL_CTL_ADD, conn_fd, &add_conn) < 0) {
              perror("Adding connection to epoll_ctl failed");
              close(conn_fd);
              break;
            }
            // Record metadata and prepare for receiving data.
            conn->fd = conn_fd;
            conn->open_time = clock();
            if (conn->buf == NULL) {
              conn->buf_cap = KILOBYTE;
              conn->buf_size = 0;
              conn->buf = malloc(KILOBYTE);
            }

            conn_fd = 0;
            break;
          }
        }
        assert(conn_fd == 0);
      } else if (idx < MAX_CONCURRENCY) {
        // A connection has had events, handle each one.
        Connection *conn = &resources->conns[idx];
        assert(idx < MAX_CONCURRENCY && conn->fd > 0);

        if ((event->events & EPOLLIN) > 0) {
          while (true) {
            // Read all of the data before returning to epoll_wait.
            inta ret = recv(conn->fd, &conn->buf[conn->buf_size], conn->buf_cap - conn->buf_size,
                            MSG_DONTWAIT);
            if (ret < 0) {
              if (errno != EAGAIN || errno != EWOULDBLOCK) {
                perror("Failed to receive data from a TCP connection");
                free_conn(resources, conn);
              }
              break;
            } else if (ret == 0) {
              break;
            }

            conn->buf_size += ret;
            if (conn->buf_size >= MAX_SCRIPT_SIZE) {
              fprintf(stderr,
                      "TCP connection exceeded maximum allowed script size of %" PRIu64 "\n",
                      MAX_SCRIPT_SIZE);
              free_conn(resources, conn);
              break;
            } else if (conn->buf_size >= conn->buf_cap) {
              conn->buf_cap *= 2;
              conn->buf = realloc(conn->buf, conn->buf_cap);
            }
          }
        }
        // The connection could have been closed above.
        if (conn->fd > 0 && (event->events & (EPOLLRDHUP | EPOLLHUP)) > 0) {
          // The connection has terminated, we can now validate and run the script.
          bool is_authentic = false;
          time_t now = time(NULL);

          /*A bash script whose 1st line is the signature of the rest of the bash file.*/
          // A raw public key signature may and often will incidentally contain a newline character.
          // So we need a way to tell apart an incidental newline from the newline separating the
          // signature and the script. One option is to use an encoding scheme for the signature,
          // but this is dangerous as it introduces nonstandard complexity and ambiguity. It would
          // be ideal if we can use a standard format for signatures, but the design specs
          // specifically ask for a format with the signature on the first line. Since signatures
          // are fixed-size, we can interpret every input byte less than the signature size as
          // unambiguously part of the signature. Furthermore, if the first line is just a
          // signature, we cannot easily include a key identifier with the script. So we have to try
          // to authenticate with each public key until we find a match. This is safe to do, just
          // not very efficient.
          for_each_lt(i, resources->keys_size) {
            PubKey *pub_key = &resources->keys[i];
            if (now > pub_key->expiry) {
              // This key has expired and should be removed.
              if (resources->keys_size > 1) {
                // Swap remove.
                swap(PubKey, pub_key, &resources->keys[resources->keys_size - 1]);
                resources->keys_size -= 1;
                i -= 1;
                continue;
              } else {
                fprintf(stderr, "All certificates have expired, closing server\n");
                return -1;
              }
            }

            uinta sig_end = pub_key->exp_sig_size;
            uinta script_start = pub_key->exp_sig_size + 1;
            if (script_start <= conn->buf_size && conn->buf[sig_end] == '\n') {
              byte *script = &conn->buf[script_start];
              uinta script_size = conn->buf_size - script_start;
              if (pub_key_verify(pub_key, script, script_size, conn->buf, sig_end)) {
                // The signature is valid, so execute the script.
                is_authentic = true;
                resources->script_n += 1;
                exec_script(script, script_size, resources->script_n);
                break;
              }
            }
          }
          if (!is_authentic) {
            fprintf(stderr, "Remote bash script could not be authenticated, aborting execution\n");
          }

          free_conn(resources, conn);
        }
        if (conn->fd > 0 && (event->events & EPOLLERR) > 0) {
          free_conn(resources, conn);
        }
      } else {
        fprintf(stderr, "Epoll returned invalid data\n");
        return -1;
      }
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  Resources resources = {0};
  int ret = main_protected(&resources, argc, argv);
  free_all(&resources);
  return ret;
}
