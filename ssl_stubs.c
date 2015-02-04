/* Portions of code are based on OCaml-ssl C bindings with Openssl
 Original copyright from OCaml-ssl project

 Copyright (C) 2003-2005 Samuel Mimram


 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* rsakey_info structure, copied from OpenSC */
struct rsakey_info {
    unsigned char   *modulus;
    int     modulus_len;
    unsigned char   *public_exponent;
    int     public_exponent_len;
    unsigned char   *private_exponent;
    int     private_exponent_len;
    unsigned char   *prime_1;
    int     prime_1_len;
    unsigned char   *prime_2;
    int     prime_2_len;
    unsigned char   *exponent_1;
    int     exponent_1_len;
    unsigned char   *exponent_2;
    int     exponent_2_len;
    unsigned char   *coefficient;
    int     coefficient_len;
};

/******************
 * Initialization *
 ******************/

CAMLprim value ocaml_ssl_init(value unit)
{
  SSL_library_init();
  SSL_load_error_strings();

  return Val_unit;
}

/*********************************
 * Certificate-related functions *
 *********************************/

#define Cert_val(v) (*((X509**)Data_custom_val(v)))

static void finalize_cert(value block)
{
  X509 *cert = Cert_val(block);
  X509_free(cert);
}

static struct custom_operations cert_ops =
{
  "ocaml_ssl_cert",
  finalize_cert,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

CAMLprim value ocaml_ssl_read_certificate(value vfilename)
{
  value block;
  char *filename = String_val(vfilename);
  X509 *cert = NULL;
  FILE *fh = NULL;

  if((fh = fopen(filename, "r")) == NULL)
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));

  caml_enter_blocking_section();
  if((cert = d2i_X509_fp(fh, NULL)) == NULL)
  {
    fclose(fh);
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));
  }
  fclose(fh);
  caml_leave_blocking_section();

  block = caml_alloc_custom(&cert_ops, sizeof(X509*), 0, 1);
  Cert_val(block) = cert;
  return block;
}

CAMLprim value ocaml_ssl_get_issuer(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);

  caml_enter_blocking_section();
  char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  caml_leave_blocking_section();
  if (!issuer) caml_raise_not_found ();

  CAMLreturn(caml_copy_string(issuer));
}

CAMLprim value ocaml_ssl_get_subject(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);

  caml_enter_blocking_section();
  char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  caml_leave_blocking_section();
  if (subject == NULL) caml_raise_not_found ();

  CAMLreturn(caml_copy_string(subject));
}

/* Ugly macro to abstract the C->Caml value */
#define CONV_CAML_ARRAY(COUNTER, TMP, VRES, CHAR_ARRAY, LEN) \
    do { \
      VRES = caml_alloc(LEN, 0); \
      for (COUNTER = 0; COUNTER < LEN; COUNTER++) {\
        TMP = Val_int(CHAR_ARRAY[COUNTER]);\
        modify(&Field(VRES, COUNTER), TMP);\
      }\
    } while (0)

CAMLprim value ocaml_ssl_get_subject_asn1(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);
  X509_NAME *name = NULL;
  unsigned char *der_subject = NULL ;
  int der_len = 0;
  int i = 0;
  value tmp;
  value _vres;

  caml_enter_blocking_section();
  /* Get x509_name corresponding to subject */
  name = X509_get_subject_name(cert);
  if(!name){
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));
  }

  der_len = i2d_X509_NAME(name, &der_subject);

  caml_leave_blocking_section();
  if (!der_subject) caml_raise_not_found ();

  CONV_CAML_ARRAY(i, tmp, _vres, der_subject, der_len);

  CAMLreturn(_vres);
}

CAMLprim value ocaml_ssl_get_issuer_asn1(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);
  X509_NAME *name = NULL;
  unsigned char *der_issuer = NULL ;
  int der_len = 0;
  int i = 0;
  value tmp;
  value _vres;

  caml_enter_blocking_section();
  /* Get x509_name corresponding to issuer */
  name = X509_get_issuer_name(cert);
  if(!name){
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));
  }

  der_len = i2d_X509_NAME(name, &der_issuer);

  caml_leave_blocking_section();
  if (!der_issuer) caml_raise_not_found ();

  CONV_CAML_ARRAY(i, tmp, _vres, der_issuer, der_len);

  CAMLreturn(_vres);
}

CAMLprim value ocaml_ssl_get_serialnumber_asn1(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);
  unsigned char *der_serialnumber = NULL ;
  int der_len = 0;
  int i;
  value tmp;
  value _vres;

  caml_enter_blocking_section();

  der_len = i2d_ASN1_INTEGER(cert->cert_info->serialNumber, &der_serialnumber);

  caml_leave_blocking_section();
  if (!der_serialnumber) caml_raise_not_found ();
  CONV_CAML_ARRAY(i, tmp, _vres, der_serialnumber, der_len);

  CAMLreturn(_vres);
}

#define RSA_GET_BN(LOCALNAME, BNVALUE) \
    do { \
        rsa->LOCALNAME = malloc(BN_num_bytes(BNVALUE)); \
        if (!rsa->LOCALNAME) {\
            printf("malloc() failure\n"); \
            exit(1);\
        }\
        rsa->LOCALNAME##_len = BN_bn2bin(BNVALUE, rsa->LOCALNAME); \
    } while (0)

/* Read DER values contained in data and construct a rsa structure */
static int
parse_rsa_private_key(struct rsakey_info *rsa, unsigned char *data, int len)
{
    RSA *r = NULL;
    const unsigned char *p;

    p = data;
    r = d2i_RSAPrivateKey(NULL, &p, len);
    if (!r) {
        printf("OpenSSL error during RSA private key parsing");
        exit(1);
    }
    RSA_GET_BN(modulus, r->n);
    RSA_GET_BN(public_exponent, r->e);
    RSA_GET_BN(private_exponent, r->d);
    RSA_GET_BN(prime_1, r->p);
    RSA_GET_BN(prime_2, r->q);
    RSA_GET_BN(exponent_1, r->dmp1);
    RSA_GET_BN(exponent_2, r->dmq1);
    RSA_GET_BN(coefficient, r->iqmp);

    return 0;
}

/* Read DER values contained in data and construct a rsa structure */
static void parse_rsa_public_key(struct rsakey_info *rsa,
        unsigned char *data, int len)
{
    RSA *r = NULL;
    const unsigned char *p;

    p = data;
    r = d2i_RSA_PUBKEY(NULL, &p, len);

    if (!r) {
        r = d2i_RSAPublicKey(NULL, &p, len);
    }

    if (!r) {
        printf("OpenSSL error during RSA public key parsing");
        exit(1);
    }
    RSA_GET_BN(modulus, r->n);
    RSA_GET_BN(public_exponent, r->e);
}

CAMLprim value ocaml_ssl_get_private_key_asn1(value privkey)
{
  CAMLparam1(privkey);
  struct rsakey_info rsa;
  unsigned char *privkey_data = NULL;
  int len;
  int i = 0;

  value tmp;
  value _vresult;
  value _vres[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  caml_enter_blocking_section();

  memset(&rsa,  0, sizeof(rsa));

  len = caml_string_length(privkey);
  if(len <= 0){
    caml_invalid_argument("invalid string data");
  }
  privkey_data = String_val(privkey);

  if(!privkey_data){
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));
  }
  parse_rsa_private_key(&rsa, privkey_data, len);

  caml_leave_blocking_section();

  CONV_CAML_ARRAY(i, tmp, _vres[0], rsa.modulus, rsa.modulus_len);
  CONV_CAML_ARRAY(i, tmp, _vres[1], rsa.public_exponent, rsa.public_exponent_len);
  CONV_CAML_ARRAY(i, tmp, _vres[2], rsa.private_exponent, rsa.private_exponent_len);
  CONV_CAML_ARRAY(i, tmp, _vres[3], rsa.prime_1, rsa.prime_1_len);
  CONV_CAML_ARRAY(i, tmp, _vres[4], rsa.prime_2, rsa.prime_2_len);
  CONV_CAML_ARRAY(i, tmp, _vres[5], rsa.exponent_1, rsa.exponent_1_len);
  CONV_CAML_ARRAY(i, tmp, _vres[6], rsa.exponent_2, rsa.exponent_2_len);
  CONV_CAML_ARRAY(i, tmp, _vres[7], rsa.coefficient, rsa.coefficient_len);

  _vresult = caml_alloc_small(8, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];
  Field(_vresult, 2) = _vres[2];
  Field(_vresult, 3) = _vres[3];
  Field(_vresult, 4) = _vres[4];
  Field(_vresult, 5) = _vres[5];
  Field(_vresult, 6) = _vres[6];
  Field(_vresult, 7) = _vres[7];

  CAMLreturn(_vresult);
}

CAMLprim value ocaml_ssl_get_public_key_asn1(value pubkey)
{
  CAMLparam1(pubkey);
  struct rsakey_info rsa;
  unsigned char *pubkey_data = NULL;
  int len;
  int i = 0;

  value tmp;
  value _vresult;
  value _vres[2] = {0, 0,};

  caml_enter_blocking_section();

  memset(&rsa,  0, sizeof(rsa));

  len = caml_string_length(pubkey);
  if(len <= 0){
    caml_invalid_argument("invalid string data");
  }
  pubkey_data = String_val(pubkey);

  if(!pubkey_data){
    caml_raise_constant(*caml_named_value("ssl_exn_certificate_error"));
  }
  parse_rsa_public_key(&rsa, pubkey_data, len);

  caml_leave_blocking_section();

  CONV_CAML_ARRAY(i, tmp, _vres[0], rsa.modulus, rsa.modulus_len);
  CONV_CAML_ARRAY(i, tmp, _vres[1], rsa.public_exponent, rsa.public_exponent_len);

  _vresult = caml_alloc_small(2, 0);
  Field(_vresult, 0) = _vres[0];
  Field(_vresult, 1) = _vres[1];

  CAMLreturn(_vresult);
}
