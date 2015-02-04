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

IFDEF WITH_OCAML_SSL THEN
type certificate
external init : unit -> unit = "ocaml_ssl_init"
external read_certificate : string -> certificate
  = "ocaml_ssl_read_certificate"
external get_issuer : certificate -> string = "ocaml_ssl_get_issuer"
external get_subject : certificate -> string = "ocaml_ssl_get_subject"
external get_subject_asn1 : certificate -> char array = "ocaml_ssl_get_subject_asn1"
external get_issuer_asn1 : certificate -> char array = "ocaml_ssl_get_issuer_asn1"
external get_serialnumber_asn1 : certificate -> char array = "ocaml_ssl_get_serialnumber_asn1"
external get_private_key_asn1 : string -> char array * char array * char array * char array * char array * char array * char array * char array  = "ocaml_ssl_get_private_key_asn1"
external get_public_key_asn1 : string -> char array * char array  = "ocaml_ssl_get_public_key_asn1"
ENDIF

IFDEF WITH_OCAML_X509 THEN

val init : unit -> unit

val read_certificate : string -> (string, int list * Asn1.asn1_value) Hashtbl.t

val get_subject_asn1 : (string, int list * Asn1.asn1_value) Hashtbl.t -> char array 
val get_issuer_asn1 : (string, int list * Asn1.asn1_value) Hashtbl.t -> char array
val get_serialnumber_asn1 : (string, int list * Asn1.asn1_value) Hashtbl.t -> char array

val get_public_key_asn1 : string -> char array * char array

val get_private_key_asn1 : string -> char array * char array * char array * char array * char array * char array * char array * char array

ENDIF
