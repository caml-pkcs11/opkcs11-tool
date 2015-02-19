#!/bin/sh

echo "[Generating configure file ...]"
aclocal
autoconf configure.ac > configure

echo "  |-> Run ./configure with the desired options, and then make"
chmod +x ./configure
