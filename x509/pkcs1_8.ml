(* WARNING: this is a beta version    *)
(* Improvement and fixes are expected *)

(* PKCS#1 public and private keys ASN.1 representation *)
exception PKCS1_Bad_OID
exception PKCS1_ASN1_parse_error of string

(* A container is either a Bitstring, an Octetstring or nothing *)
let optional_bit_container name insider = 
    if compare insider Asn1.None_R = 0 then
      Asn1.Option_R("", [ Asn1.Bitstring_R(name, [ ]); Asn1.Octetstring_R(name, [ ]) ])
    else
      Asn1.Option_R("", [ Asn1.Bitstring_R(name, [ insider ]); Asn1.Octetstring_R(name, [ insider ]); insider ])

let pbeWithSHAAnd128BitRC4_parameters = Asn1.Sequence_R("pbeWithSHAAnd128BitRC4_parameters", 1, 1, [
   optional_bit_container "pbeWithSHAAnd128BitRC4_parameters_1" Asn1.None_R;
   Asn1.Integer_R("pbeWithSHAAnd128BitRC4_parameters_2")
])

let optional_parameters name = Asn1.Option_R((String.concat name ["_option"]), 
                               [ Asn1.Null_R("null_parameters"); pbeWithSHAAnd128BitRC4_parameters; Asn1.None_R ])

let algorithm_identifiers name oids_names = 
  let the_oids_list = List.map (
    fun oid_name -> Oids.get_oids_from_name oid_name Oids.oids
  ) oids_names in
  let oids = List.concat the_oids_list in
  Asn1.Sequence_R(name ^ ".AlgorithmIdentifier", 1, 1, [
      Asn1.OID_R(name ^ ".AlgorithmIdentifier.Algorithm", oids);
      optional_parameters (name ^ ".AlgorithmIdentifier.Parameters")
  ])


(********************************)
(* PKCS1 public key ASN1 scheme *)

class pkcs_rsa_public_key =
  object (s)
    val mutable modulus : (string*string) option = None
    val mutable public_exponent : (string*string) option = None
    method get field = match field with
      | "modulus" -> (match modulus with | None -> ("", "") | Some(x) -> x)
      | "public_exponent" -> (match public_exponent with | None -> ("", "") | Some(x) -> x)
      | _ -> let s = Printf.sprintf "RSA public key class get field: field %s is unknown" field in failwith s
    method set field a = match field with
      | "modulus" -> modulus <- Some(a)
      | "public_exponent" -> public_exponent <- Some(a)
      | _ -> let s = Printf.sprintf "RSA public key class set field: field %s is unknown" field in failwith s
  end

(********************************)
type pkcs_public_key = 
  | PKCS_RSA_public_key of pkcs_rsa_public_key

let pkcs_rsa_class_from_pkcstree pkcs_tree =
  let the_class = new pkcs_rsa_public_key in
  the_class#set "modulus" (Asn1.get_field_of_asn1_representation_from_node_pos pkcs_tree [0; 0; 0]);
  the_class#set "public_exponent" (Asn1.get_field_of_asn1_representation_from_node_pos pkcs_tree [0; 0; 1]);
  (PKCS_RSA_public_key(the_class))

let rsa_public_key name = Asn1.Sequence_R("", 1, 1, [
  Asn1.Integer_R(name ^ ".Modulus"); 
  Asn1.Integer_R(name ^ ".PublicExponent");
])

let pkcs1_rsa_public_key_asn1_scheme name = Asn1.Sequence_R("", 1, 1, [
  algorithm_identifiers (name ^ "PublicKeyInfoSequence") ["rsaEncryption"];
  optional_bit_container "Values" (
    rsa_public_key (name ^ "RSAPublicKey");
  );
])


(********************************)
(* PKCS1 private key scheme *)
let other_prime_infos name = Asn1.Option_R("", [ 
  (*** Take ASN1 MAX = 100 here ***)
  Asn1.Sequence_R(name ^ "OthePrimeInfos", 0, 100, [
    Asn1.Integer_R(name ^ "prime");
    Asn1.Integer_R(name ^ "exponent");
    Asn1.Integer_R(name ^ "coefficient")	
  ]);
  Asn1.None_R
])

let pkcs1_rsa_private_key_asn1_scheme name =
Asn1.Sequence_R(name ^ "RSAPrivateKey", 1, 1, [
  Asn1.Integer_R("RSAPrivateKey.RSAPrivateKey_version");
  Asn1.Integer_R("RSAPrivateKey.Modulus");
  Asn1.Integer_R("RSAPrivateKey.PublicExponent");
  Asn1.Integer_R("RSAPrivateKey.PrivateExponent");
  Asn1.Integer_R("RSAPrivateKey.Prime1");
  Asn1.Integer_R("RSAPrivateKey.Prime2");
  Asn1.Integer_R("RSAPrivateKey.Exponent1");
  Asn1.Integer_R("RSAPrivateKey.Exponent2");
  Asn1.Integer_R("RSAPrivateKey.Coefficient");
  other_prime_infos name
])

(*** Exported class for RSA private key ***)
class pkcs_rsa_private_key_other_prime_info =
  object (s)
    val mutable prime : (string*string) option = None
    val mutable exponent : (string*string) option = None
    val mutable coefficient : (string*string) option = None
  end

class pkcs_rsa_private_key =
  object (s)
    val mutable version : (string*string) option = None
    val mutable modulus : (string*string) option = None
    val mutable public_exponent : (string*string) option = None
    val mutable private_exponent : (string*string) option = None
    val mutable prime1 : (string*string) option = None
    val mutable prime2 : (string*string) option = None
    val mutable exponent1 : (string*string) option = None
    val mutable exponent2 : (string*string) option = None
    val mutable coefficient : (string*string) option = None
    val mutable othe_prime_info : pkcs_rsa_private_key_other_prime_info list option = None
  end

(********************************)

                          
(*********************************)
(* PKCS8 private key ASN1 scheme *)
(* Unencrypted                   *)
let pkcs8_unencrypted_rsa_private_key_asn1_scheme name = 
Asn1.Sequence_R("PrivateKeyInfo", 1, 1, [
        Asn1.Integer_R("PrivateKeyInfo_version");
        algorithm_identifiers (name ^ "PrivateKeyInfo") ["rsaEncryption"];
  	optional_bit_container "PrivateKeyInfo_values" (
          pkcs1_rsa_private_key_asn1_scheme name
        )
])
(********************************)

(*********************************)
(* PKCS8 private key ASN1 scheme *)
(* Encrypted                     *)
let pkcs8_encrypted_rsa_private_key_asn1_scheme name = 
  Asn1.Sequence_R("EncryptedPrivateKeyInfo", 1, 1, [
        algorithm_identifiers (name ^ "EncryptedPrivateKeyInfo") ["pbeWithSHAAnd128BitRC4"];
  	optional_bit_container (name ^ "KeyContainer") Asn1.None_R
])
(********************************)



(*********************************)
(* PKCS1 digest info             *)
(*********************************)
let digest_info name =
Asn1.Sequence_R("DigestInfo", 1, 1, [
        Asn1.Integer_R(name ^ "DigestInfo.PrivateKeyInfo_version");
        algorithm_identifiers (name ^ "DigestInfo.DigestAlgorithmIdentifier") ["md2"; "md4"; "md5"; "sha1"; "sha256"; "sha512"; "ripemd160"; "ripemd128"; "ripemd256"];
        Asn1.Octetstring_R("DigestInfo.Digest", [])
])


(*********************************)
let get_key_from_der in_der = 
  (* First, we decode *)
  let decoded_asn1 = (try Asn1.decode_ber 0 in_der false false 
    with _ -> raise(PKCS1_ASN1_parse_error "Error when doing ASN1 decode for PKCS1/8 keys")) in
  (* Try to get a PKCS1 public key *)
  let (check_pub, pub_key) = Asn1.check_asn1_scheme decoded_asn1 (pkcs1_rsa_public_key_asn1_scheme "") in
  let (check_priv1, priv_key1) = Asn1.check_asn1_scheme decoded_asn1 (pkcs8_unencrypted_rsa_private_key_asn1_scheme "") in
  let (check_priv2, priv_key2) = Asn1.check_asn1_scheme decoded_asn1 (pkcs8_encrypted_rsa_private_key_asn1_scheme "") in
  if check_pub = true then
    let _ = Printf.printf "Got a PKCS1 public key\n" in
    Asn1.print_checked_asn1_scheme pub_key;
  else if check_priv1 = true then
    (* Try to get a PKCS1 private key *)
    let _ = Printf.printf "Got a PKCS8 unencrypted private key\n" in
    Asn1.print_checked_asn1_scheme priv_key1;
  else if check_priv2 = true then
    (* Try to get a PKCS1 private key *)
    let _ = Printf.printf "Got a PKCS8 encrypted private key\n" in
    Asn1.print_checked_asn1_scheme priv_key2;
  ()
