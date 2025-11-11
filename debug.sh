#!/bin/bash
# I don't consider this project complex enough to warrant a make file.
clang -g -O0 src/main.c src/x509.c src/crypto.c -lssl -lcrypto -o server.out
