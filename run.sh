#!/usr/bin/env bash
# Stagefright демо-г build хийж valgrind дор ажиллуулна.
# Курсын серверт (Debian 13, gcc 14.2.0, valgrind 3.24) шалгасан.
set -eu

CC=${CC:-gcc}
CFLAGS="-std=c11 -Wall -Wextra -g -O0"

echo "$ $CC $CFLAGS -o demo demo.c"
$CC $CFLAGS -o demo demo.c

# --exit-on-first-error: эхний invalid write дээр зогсоно (count удаа бичих
# гүйлт wrap-ийн дараа 10^9 давталт хийхээс сэргийлнэ).
echo "$ valgrind --exit-on-first-error=yes --error-exitcode=42 ./demo"
echo
valgrind --exit-on-first-error=yes --error-exitcode=42 ./demo || true
