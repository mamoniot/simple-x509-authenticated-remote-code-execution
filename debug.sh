#!/bin/bash
# I don't consider this project complex enough to warrant a make file.
clang -g -O0 src/main.c src/x509.c src/crypto.c src/exec.c src/read_cert.c -lcrypto -o server.out
