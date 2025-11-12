#include "sys/wait.h"
#include "unistd.h"
#include "stdio.h"

#include "exec.h"


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
