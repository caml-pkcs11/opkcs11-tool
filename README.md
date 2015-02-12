# opkcs11-tool

This software is a computer program whose purpose is to offer CLI capabilities
to administer and use PKCS\#11 devices.
It is similar to OpenSC's pkcs11-tool but offers a more complete feature set.

Example of CLI capabilities:
  * Use newer encryption schemes:
    * use EC keys
    * support for PSS signature (CKM\_RSA\_PKCS\_PSS)
    * support for OAEP encryption (CKM\_RSA\_PKCS\_OAEP)
  * Manage object creation using template from the CLI:
    * specify key usages, label, id
  * Change attributes from the CLI
  * Search for objects using attributes from the CLI
  * ...

## Authors

  * Ryad Benadjila (<mailto:ryad.benadjila@ssi.gouv.fr>)
  * Thomas Calderon (<mailto:thomas.calderon@ssi.gouv.fr>)

## Quickstart - Linux
Download the sources using GIT:

    git clone --recursive git://github.com/ANSSI-FR/opkcs11-tool.git

Dependencies for a Debian/Ubuntu machine:

    sudo apt-get install autoconf make gcc ocaml-nox camlidl coccinelle camlp4

Building:

    cd opkcs11-tool
    make

## Quickstart - Windows
It is possible to compile opkcs11-tool for Windows 32/64.
Detailed instructions will be provided at a later time.

## Documentation
A more complete documentation will be provided at a later time.
Please see below for a couple of examples.

## Examples using SoftHSM (initialized)

Create a new signature-only RSA key-pair (requires a PIN):

    ./opkcs11-tool -module /usr/lib/softhsm/libsofthsm.so -l \
    -keypairgen -keypairsize 1024 -mech rsa \
    -priv-attributes "CKA_TOKEN=TRUE,CKA_SIGN=TRUE,CKA_SIGN_RECOVER=FALSE,CKA_DECRYPT=FALSE,CKA_UNWRAP=FALSE"\
    -pub-attributes "CKA_PRIVATE=FALSE,CKA_VERIFY=TRUE,CKA_VERIFY_RECOVER=FALSE,CKA_ENCRYPT=FALSE,CKA_WRAP=FALSE"\
    -label sign_key
    >Using slot 0.
    >Enter PIN:******
    >C_GenerateKeyPair ret: cKR_OK

Hash and sign (RSA\_PSS) some data using the new key (requires a PIN):

    ./opkcs11-tool -module /usr/lib/softhsm/libsofthsm.so -l -label sign_key \
    -s -mech CKM_SHA256_RSA_PKCS -in /etc/fstab -out /tmp/hash-and-sign-fstab
    >Using slot 0.
    >Enter PIN:******
    >Signed data (in hex): '...'
    >Writing data to /tmp/hash-and-sign-fstab

Verify the signed data:

    ./opkcs11-tool -module /usr/lib/softhsm/libsofthsm.so -label sign_key \
    -v -mech CKM_SHA256_RSA_PKCS_PSS -in /etc/fstab -verify /tmp/hash-and-sign-fstab
    >Verify operation returned : cKR_OK
    
    dd if=/dev/zero of=/tmp/hash-and-sign-fstab bs=1 count=128
    ./opkcs11-tool -module /usr/lib/softhsm/libsofthsm.so -label sign_key \
    -mech CKM_SHA256_RSA_PKCS_PSS -in /etc/fstab -verify /tmp/hash-and-sign-fstab
    >Fatal error: exception Failure("cKR_SIGNATURE_INVALID")
