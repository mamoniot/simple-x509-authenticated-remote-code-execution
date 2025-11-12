#ifndef EXEC__H_INCLUDE
#define EXEC__H_INCLUDE

#include "basic.h"

// Execute the bash script contained in script and script_size in a new child process that shares
// our stdout. A status line will be output to stdout prior to execution. script_n is used to
// identify this script in the status line. This function will block until the bash script completes
// execution.
//
// This function uses system calls specific to POSIX, and thus is only portable to BSD, linux and
// macOS.
void exec_script(byte *script, uinta script_size, uint32 script_n);

#endif
