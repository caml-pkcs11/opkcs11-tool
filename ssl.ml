IFDEF WITH_OCAML_SSL THEN
(**************************************************************)
(** Portions of code are based on OCaml-ssl C bindings with Openssl ***)
(* Original copyright from OCaml-ssl project *)
(*
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
 *)

type certificate

external init : unit -> unit = "ocaml_ssl_init"

external read_certificate : string -> certificate = "ocaml_ssl_read_certificate"

external get_issuer : certificate -> string = "ocaml_ssl_get_issuer"

external get_subject : certificate -> string = "ocaml_ssl_get_subject"

external get_subject_asn1 : certificate -> char array = "ocaml_ssl_get_subject_asn1"

external get_issuer_asn1 : certificate -> char array = "ocaml_ssl_get_issuer_asn1"

external get_serialnumber_asn1 : certificate -> char array = "ocaml_ssl_get_serialnumber_asn1"

external get_private_key_asn1 : string -> char array * char array * char array * char array * char array * char array * char array * char array  = "ocaml_ssl_get_private_key_asn1"
external get_public_key_asn1 : string -> char array * char array  = "ocaml_ssl_get_public_key_asn1"
(**************************************************************)
ENDIF


(**************************************************************)
(** Case where we use full OCaml X509 parsing *****************)
IFDEF WITH_OCAML_X509 THEN

(* No need to init the openssl library here *)
let init _ = ()

IFDEF OCAML_NO_BYTES_MODULE THEN
(* Read a certificate from a path *)
let read_certificate cert_path =
  let in_der = P11_common.read_file ~set_binary:true cert_path in
  (* Get a parsed x509 object *)
  let decoded_asn1 = (try Asn1.decode_ber 0 in_der false false
    with _ ->
      let s = Printf.sprintf "X509 (ASN1) parse error when reading %s\n" cert_path in
      raise(X509.X509_ASN1_parse_error s)) in
  let (check_x509, x509) = Asn1.check_asn1_scheme decoded_asn1 X509.x509_certificate_asn1_scheme in
  if check_x509 = true then
    (* We have an x509, return it *)
    (x509)
  else
    (* Not an x509, raise an error *)
    let s = Printf.sprintf "X509 parse error when reading %s (valid ASN1 but not an X509)\n" cert_path in
    raise(X509.X509_ASN1_parse_error s)
ENDIF
IFNDEF OCAML_NO_BYTES_MODULE THEN
(* Read a certificate from a path *)
let read_certificate cert_path =
  let in_der = P11_common.read_file ~set_binary:true cert_path in
  (* Get a parsed x509 object *)
  let decoded_asn1 = (try Asn1.decode_ber 0 (Bytes.to_string in_der) false false
    with _ ->
      let s = Printf.sprintf "X509 (ASN1) parse error when reading %s\n" cert_path in
      raise(X509.X509_ASN1_parse_error s)) in
  let (check_x509, x509) = Asn1.check_asn1_scheme decoded_asn1 X509.x509_certificate_asn1_scheme in
  if check_x509 = true then
    (* We have an x509, return it *)
    (x509)
  else
    (* Not an x509, raise an error *)
    let s = Printf.sprintf "X509 parse error when reading %s (valid ASN1 but not an X509)\n" cert_path in
    raise(X509.X509_ASN1_parse_error s)
ENDIF

(* Get the subject ASN1 value from an X509 certificate *)
let get_subject_asn1 cert =
  let (asn1_string, _) = (try Asn1.get_field_of_asn1_representation_from_node_pos cert [0; 5] with
    _ -> let s = Printf.sprintf "X509 parse error when searching for subject\n" in
         raise(X509.X509_ASN1_parse_error s)  
  ) in
  (Pkcs11.string_to_char_array asn1_string)

(* Get the issuer ASN1 value from an X509 certificate *)
let get_issuer_asn1 cert =
  let (asn1_string, _) = (try Asn1.get_field_of_asn1_representation_from_node_pos cert [0; 3] with
    _ -> let s = Printf.sprintf "X509 parse error when searching for issuer\n" in
        raise(X509.X509_ASN1_parse_error s)
  ) in
  (Pkcs11.string_to_char_array asn1_string)

(* Get the serial number ASN1 value from an X509 certificate *)
let get_serialnumber_asn1 cert =
  let (asn1_string, _) = (try Asn1.get_field_of_asn1_representation_from_node_pos cert [0; 1] with
    _ -> let s = Printf.sprintf "X509 parse error when searching for serial number\n" in
        raise(X509.X509_ASN1_parse_error s)
  ) in
  (Pkcs11.string_to_char_array asn1_string)

let asn1_int_to_big_int integer =
  (* Function that removes the possible prepending 00 on ASN1 integers *)
  if compare (String.length integer) 0 = 0 then
    (integer)
  else
    if compare integer.[0] (Char.chr 0x00) = 0 then
      (String.sub integer 1 (String.length integer - 1))
    else
      (integer)

(* Get the public key from an input ASN1 buffer *)
let get_public_key_asn1 in_der =
  (* The input buffer should be in a PKCS#1/8 form *)
  let decoded_asn1 =  (try Asn1.decode_ber 0 in_der false false
    with _ -> 
      let s = Printf.sprintf "PKCS#1/8 (ASN1) parse error\n" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)) in
  let (check_public_key, public_key) = Asn1.check_asn1_scheme decoded_asn1 (Pkcs1_8.pkcs1_rsa_public_key_asn1_scheme "") in
  if check_public_key = true then
    (* We have an public key, get its elements *)
    let (_, modulus) = (try Asn1.get_field_of_asn1_representation_from_node_pos public_key [1; 0; 0] with
      _ -> let s = Printf.sprintf "PKCS#1/8 (ASN1) parse error when getting modulus of public key\n" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, exponent) = (try Asn1.get_field_of_asn1_representation_from_node_pos public_key [1; 0; 1] with
      _ -> let s = Printf.sprintf "PKCS#1/8 (ASN1) parse error when getting exponent of public key\n" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in    
    (Pkcs11.string_to_char_array (asn1_int_to_big_int modulus), Pkcs11.string_to_char_array (asn1_int_to_big_int exponent))
  else
    (* Not an x509, raise an error *)    
    let s = Printf.sprintf "PKCS#1/8 parse error (valid ASN1 but not a PKCS#1/8 structure)\n" in
    raise(Pkcs1_8.PKCS1_ASN1_parse_error s)


(* Get the private key from an input ASN1 buffer *)
let get_private_key_asn1 in_der =
  (* The input buffer should be in a PKCS#1 form *)
  let decoded_asn1 =  (try Asn1.decode_ber 0 in_der false false
    with _ -> 
      let s = Printf.sprintf "PKCS#1 (ASN1) parse error\n" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)) in
  let (check_private_key, private_key) = Asn1.check_asn1_scheme decoded_asn1 (Pkcs1_8.pkcs1_rsa_private_key_asn1_scheme "") in
  if check_private_key = true then
    (* We have an public key, get its elements *)
    let (_, modulus) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [1] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting modulus of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, publicexponent) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [2] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting public exponent of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, privateexponent) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [3] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting private exponent of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, prime1) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [4] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting prime1 of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, prime2) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [5] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting prime2 of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, exponent1) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [6] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting exponent1 of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, exponent2) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [7] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting exponent2 of private key\n" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    let (_, coefficient) = (try Asn1.get_field_of_asn1_representation_from_node_pos private_key [8] with
       _ -> let s = Printf.sprintf "PKCS#1 (ASN1) parse error when getting coefficient of private key" in
      raise(Pkcs1_8.PKCS1_ASN1_parse_error s)
    ) in
    (Pkcs11.string_to_char_array (asn1_int_to_big_int modulus), Pkcs11.string_to_char_array (asn1_int_to_big_int publicexponent), Pkcs11.string_to_char_array (asn1_int_to_big_int privateexponent), Pkcs11.string_to_char_array (asn1_int_to_big_int prime1), Pkcs11.string_to_char_array (asn1_int_to_big_int prime2), Pkcs11.string_to_char_array (asn1_int_to_big_int exponent1), Pkcs11.string_to_char_array (asn1_int_to_big_int exponent2), Pkcs11.string_to_char_array (asn1_int_to_big_int coefficient))
  else
    let s = Printf.sprintf "PKCS#1 (ASN1) parse error\n" in
    raise(Pkcs1_8.PKCS1_ASN1_parse_error s)

 
ENDIF


