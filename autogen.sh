#!/bin/sh

echo "[Generating configure file ...]"
aclocal
if [ "${OS}" = "Windows_NT" ]
then
  echo "  |-> Using Cygwin environment"
  cp Makefile.Win32.in Makefile.in
else
  cp Makefile.Unix.in Makefile.in
fi
autoconf configure.ac > configure

echo "  |-> Run ./configure with the desired options, and then make"
chmod +x ./configure
