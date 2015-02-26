# opkcs11-tool

Building for Win32 platform is possible using either WODI-Cygwin or MSVC.

However, it is more convenient to use the WODI-Cygwin approach as it does not
require recompiling OCaml using MSVC.

## Using WODI and Cygwin for 32 bits

First: 

  * [Download and install the OCaml WODI environment](http://wodi.forge.ocamlcore.org/download.html)
  * When installing Cygwin, configure your mirror and add the following additional packages
    * autoconf
    * automake

Second:

  * Use WODI package manager to install **camlidl**

Third, start a Cygwin shell:

    #replace test with you current user
    cd /cygdrive/c/Users/test/Downloads
    wget https://github.com/ANSSI-FR/caml-crush/archive/w32-x86.zip -O caml-crush-master.zip
    unzip caml-crush-master.zip
    wget https://github.com/ANSSI-FR/opkcs11-tool/archive/master.zip -O opkcs11-tool-master.zip
    unzip opkcs11-tool-master.zip
    cd opkcs11-tool-master
    mv ../caml-crush-master ./
    ./autogen.sh
    ./configure --with-caml-crush=caml-crush-master --host=i686-w64-mingw32
    make

At this stage you should be done. You can then test **opkcs11-tool.exe**

## Using WODI and Cygwin for 64 bits

This has not been tested yet.

## Using OCaml build with MSVC

This is known to work, documentation will be provided later.
