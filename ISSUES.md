# opkcs11-tool

## General disclaimer for X.509 parsing

The default compilation uses a minimalist OCaml ASN.1 and X.509 parsing engine.
This should not be used in production as it is provided only to parse ASN.1 DER
object in order to handle binary object prior to injecting them on a token.
This avoids requiring to link to a third-party crypto library such as OpenSSL.

If you prefer linking to OpenSSL, use:

    make opkcs11_tool_ssl

## ISSUES and LIMITATIONS of minimalist X.509 parser
### PKCS#1/8 private keys
Only PKCS#1 private keys are support at a high-level.
Parsing should be more flexible to allow PKCS#1/8 scheme as an input.
### X.509 v1 support
No X.509 v1 support, this should be fixed, you can still use the OpenSSL
version to import such objects.
### ECC support
For now, it is not supported to inject ECC objects, you can still use the
OpenSSL version to import such objects.
However, you can generate ECC keys and use them.
