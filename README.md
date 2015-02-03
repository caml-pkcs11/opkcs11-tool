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

## Introduction

## Authors

  * Ryad Benadjila (<mailto:ryad.benadjila@ssi.gouv.fr>)
  * Thomas Calderon (<mailto:thomas.calderon@ssi.gouv.fr>)
