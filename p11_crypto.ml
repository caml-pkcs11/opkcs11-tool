open Printf
open P11_common


let match_cKF_mech_value a =
  if (compare Pkcs11.cKF_HW a = 0)  then "CKF_HW"
  else if (compare Pkcs11.cKF_ENCRYPT a = 0)  then "CKF_ENCRYPT"
  else if (compare Pkcs11.cKF_DECRYPT a = 0)  then "CKF_DECRYPT"
  else if (compare Pkcs11.cKF_DIGEST a = 0)  then "CKF_DIGEST"
  else if (compare Pkcs11.cKF_SIGN a = 0)  then "CKF_SIGN"
  else if (compare Pkcs11.cKF_SIGN_RECOVER a = 0)  then "CKF_SIGN_RECOVER"
  else if (compare Pkcs11.cKF_VERIFY a = 0)  then "CKF_VERIFY"
  else if (compare Pkcs11.cKF_VERIFY_RECOVER a = 0)  then "CKF_VERIFY_RECOVER"
  else if (compare Pkcs11.cKF_GENERATE a = 0)  then "CKF_GENERATE"
  else if (compare Pkcs11.cKF_GENERATE_KEY_PAIR a = 0)  then "CKF_GENERATE_KEY_PAIR"
  else if (compare Pkcs11.cKF_WRAP a = 0)  then "CKF_WRAP"
  else if (compare Pkcs11.cKF_UNWRAP a = 0)  then "CKF_UNWRAP"
  else if (compare Pkcs11.cKF_DERIVE a = 0)  then "CKF_DERIVE"
  else if (compare Pkcs11.cKF_EXTENSION a = 0)  then "CKF_EXTENSION"
  else "CKR_UNKNOWN!"

let check_bit_on flag bit =
    (Nativeint.logand flag bit = bit)

(* FIXME: Handle unkown flags *)
let print_features flag feature =
    if (check_bit_on flag feature) then
      Printf.printf ", %s" (match_cKF_mech_value feature);
    ()

let parse_cKF_flags flags =
    let supported_features = [| Pkcs11.cKF_HW; Pkcs11.cKF_ENCRYPT; Pkcs11.cKF_DECRYPT;
                                Pkcs11.cKF_DIGEST; Pkcs11.cKF_SIGN ;Pkcs11.cKF_SIGN_RECOVER ;
                                Pkcs11.cKF_VERIFY; Pkcs11.cKF_VERIFY_RECOVER;
                                Pkcs11.cKF_GENERATE; Pkcs11.cKF_GENERATE_KEY_PAIR;
                                Pkcs11.cKF_WRAP; Pkcs11.cKF_UNWRAP;
                                Pkcs11.cKF_DERIVE; Pkcs11.cKF_EXTENSION |] in

    let _ = Array.iter (print_features flags) supported_features in
    ()

(* High level function to print CK_MECHANISM_INFO structures *)
let print_mechanism_info slot_id mech =
    let (ret_value, info_) = Pkcs11.mL_CK_C_GetMechanismInfo slot_id mech in
    let _ = check_ret ret_value C_GetMechanismInfoError false in
    dbg_print !do_verbose "C_GetMechanismInfo" ret_value;
    let msg = Printf.sprintf "  %s, keySize{%s, %s}" (Pkcs11.match_cKM_value mech)
                                                    (Nativeint.to_string info_.Pkcs11.ck_mechanism_info_min_key_size)
                                                    (Nativeint.to_string info_.Pkcs11.ck_mechanism_info_max_key_size) in
    Printf.printf "%s" msg;
    parse_cKF_flags info_.Pkcs11.ck_mechanism_info_flags;
    Printf.printf "\n";
    ()

(* High level GetMechanismList *)
let get_mechanism_list_for_slot slot_id =
    let (ret_value, _, count) = Pkcs11.mL_CK_C_GetMechanismList slot_id 0n in
    let _ = check_ret ret_value C_GetMechanismListError false in
    printf "C_GetMechanismList ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    let (ret_value, mechanism_list_, _) = Pkcs11.mL_CK_C_GetMechanismList slot_id count in
    let _ = check_ret ret_value C_GetMechanismListError false in
    printf "C_GetMechanismList ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    printf "Supported mechanisms:\n";
    (mechanism_list_)

(* Deduct RSA PSS params when supplying digested output *)
IFDEF WIN32 THEN
let get_pss_params data =
    let params = (match (String.length data) with
        | 20 -> Pkcs11.pack "200200000100000014000000"
        | 32 -> Pkcs11.pack "500200000200000020000000"
        | 48 -> Pkcs11.pack "600200000300000030000000"
        | 64 -> Pkcs11.pack "700200000400000040000000"
        | _ -> failwith "Input data len is not compatible with output of sha1|sha256|sha384|sha512") in
    (Pkcs11.string_to_char_array params)
ELSE
let get_pss_params data =
    let params = (match (String.length data) with
        | 20 -> Pkcs11.pack "200200000000000001000000000000001400000000000000"
        | 32 -> Pkcs11.pack "500200000000000002000000000000002000000000000000"
        | 48 -> Pkcs11.pack "600200000000000003000000000000003000000000000000"
        | 64 -> Pkcs11.pack "700200000000000004000000000000004000000000000000"
        | _ -> failwith "Input data len is not compatible with output of sha1|sha256|sha384|sha512") in
    (Pkcs11.string_to_char_array params)
ENDIF

IFDEF WIN32 THEN
let get_oaep_params data =
    let params = (match (data) with
        | "sha1"   -> Pkcs11.pack "200200000100000001000000"
        | "sha256" -> Pkcs11.pack "500200000200000001000000"
        | "sha384" -> Pkcs11.pack "600200000300000001000000"
        | "sha512" -> Pkcs11.pack "700200000400000001000000"
        | _ -> failwith "MGF can only be of type sha1|sha256|sha384|sha512") in
    (Pkcs11.string_to_char_array params)
ELSE
let get_oaep_params data =
    let params = (match (data) with
        | "sha1"   -> Pkcs11.pack "200200000000000001000000000000000100000000000000"
        | "sha256" -> Pkcs11.pack "500200000000000002000000000000000100000000000000"
        | "sha384" -> Pkcs11.pack "600200000000000003000000000000000100000000000000"
        | "sha512" -> Pkcs11.pack "700200000000000004000000000000000100000000000000"
        | _ -> failwith "MGF can only be of type sha1|sha256|sha384|sha512") in
    (Pkcs11.string_to_char_array params)
ENDIF

(* Initial generic mechanism attributes parsing *)
IFDEF WIN32 THEN
let get_mech_params mechanism data =
    match (Pkcs11.match_cKM_value mechanism.Pkcs11.mechanism) with
        | "cKM_SHA1_RSA_PKCS_PSS"   -> ( Pkcs11.string_to_char_array (Pkcs11.pack "200200000100000014000000"))
        | "cKM_SHA256_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "500200000200000020000000"))
        | "cKM_SHA384_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "600200000300000030000000"))
        | "cKM_SHA512_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "700200000400000040000000"))
        | "cKM_RSA_PKCS_PSS" -> (get_pss_params data)
        | "cKM_RSA_PKCS_OAEP" -> (get_oaep_params data)
        | "cKM_DES_CBC" ->      mechanism.Pkcs11.parameter
        | "cKM_DES_CBC_PAD" ->  mechanism.Pkcs11.parameter
        | "cKM_DES3_CBC" ->     mechanism.Pkcs11.parameter
        | "cKM_DES3_CBC_PAD" -> mechanism.Pkcs11.parameter
        | "cKM_AES_CBC" ->      mechanism.Pkcs11.parameter
        | "cKM_AES_CBC_PAD" ->  mechanism.Pkcs11.parameter
        | _ -> [||]
ELSE
let get_mech_params mechanism data = 
    match (Pkcs11.match_cKM_value mechanism.Pkcs11.mechanism) with
        | "cKM_SHA1_RSA_PKCS_PSS"   -> ( Pkcs11.string_to_char_array (Pkcs11.pack "200200000000000001000000000000001400000000000000"))
        | "cKM_SHA256_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "500200000000000002000000000000002000000000000000"))
        | "cKM_SHA384_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "600200000000000003000000000000003000000000000000"))
        | "cKM_SHA512_RSA_PKCS_PSS" -> ( Pkcs11.string_to_char_array (Pkcs11.pack "700200000000000004000000000000004000000000000000"))
        | "cKM_RSA_PKCS_PSS" ->  (get_pss_params data)
        | "cKM_RSA_PKCS_OAEP" -> (get_oaep_params data)
        | "cKM_DES_CBC" ->      mechanism.Pkcs11.parameter
        | "cKM_DES_CBC_PAD" ->  mechanism.Pkcs11.parameter
        | "cKM_DES3_CBC" ->     mechanism.Pkcs11.parameter
        | "cKM_DES3_CBC_PAD" -> mechanism.Pkcs11.parameter
        | "cKM_AES_CBC" ->      mechanism.Pkcs11.parameter
        | "cKM_AES_CBC_PAD" ->  mechanism.Pkcs11.parameter
        | _ -> [||]
ENDIF

let sign_some_data session mechanism privkey_ data = 
    let mech_params = get_mech_params mechanism data in

    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in

    let ret_value = Pkcs11.mL_CK_C_SignInit session mech privkey_ in
    let _ = check_ret ret_value C_SignInitError false in

    let tosign = Pkcs11.string_to_char_array data in
    let (ret_value, signed_data_) = Pkcs11.mL_CK_C_Sign session tosign in
    let _ = check_ret ret_value C_SignInitError false in

    (signed_data_)

let digest_some_data session mechanism data = 
    let ret_value = Pkcs11.mL_CK_C_DigestInit session mechanism in
    let _ = check_ret ret_value C_DigestInitError false in

    let todigest = Pkcs11.string_to_char_array data in
    let (ret_value, digested_data_) = Pkcs11.mL_CK_C_Digest session todigest in
    let _ = check_ret ret_value C_DigestError false in

    (digested_data_)

let digestupdate_some_data session mechanism data = 
    let ret_value = Pkcs11.mL_CK_C_DigestInit session mechanism in
    let _ = check_ret ret_value C_DigestInitError false in

    let todigest = Pkcs11.string_to_char_array data in
    let ret_value = Pkcs11.mL_CK_C_DigestUpdate session todigest in
    let _ = check_ret ret_value C_DigestUpdateError false in

    let (ret_value, digested_data_) = Pkcs11.mL_CK_C_DigestFinal session in
    let _ = check_ret ret_value C_DigestFinalError false in

    (digested_data_)

let verify_some_data session mechanism pubkey_ rawdata_ signed_data_ = 
    let mech_params = get_mech_params mechanism rawdata_ in

    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in


    let ret_value = Pkcs11.mL_CK_C_VerifyInit session mech pubkey_ in
    let _ = check_ret ret_value C_VerifyInitError false in

    let tocheck = Pkcs11.string_to_char_array rawdata_ in
    let signed_data_char_ = Pkcs11.string_to_char_array signed_data_ in

    let ret_value = Pkcs11.mL_CK_C_Verify session tocheck signed_data_char_ in
    let _ = check_ret ret_value C_VerifyError false in

    (ret_value)

let wrap_key session mechanism wrapping_key_ key_ = 

    let mech_params = get_mech_params mechanism !mgf_type in
    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in

    let (ret_value, wrapped_key_) = Pkcs11.mL_CK_C_WrapKey session mech wrapping_key_ key_ in
    let _ = check_ret ret_value C_WrapKeyError false in

    (wrapped_key_)

let unwrap_key session mechanism wrapping_key_ data template = 

    let mech_params = get_mech_params mechanism !mgf_type in
    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in

    let tounwrap = Pkcs11.string_to_char_array data in

    let (ret_value, unwrapped_key_) = Pkcs11.mL_CK_C_UnwrapKey session mech wrapping_key_ tounwrap template in
    let _ = check_ret ret_value C_UnwrapKeyError false in

    (unwrapped_key_)


let encrypt_some_data session mechanism key_ data = 
    let mech_params = get_mech_params mechanism !mgf_type in
    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in

    let toenc = Pkcs11.string_to_char_array data in

    let ret_value = Pkcs11.mL_CK_C_EncryptInit session mech key_ in
    let _ = check_ret ret_value C_EncryptInitError false in

    let (ret_value, enc_data_) = Pkcs11.mL_CK_C_Encrypt session toenc in
    let _ = check_ret ret_value C_EncryptError false in

    (enc_data_)

let decrypt_some_data session mechanism key_ encrypted_data = 
    let mech_params = get_mech_params mechanism !mgf_type in
    let mech = { Pkcs11.mechanism = mechanism.Pkcs11.mechanism; Pkcs11.parameter = mech_params } in

    let todec = Pkcs11.string_to_char_array encrypted_data in

    let ret_value = Pkcs11.mL_CK_C_DecryptInit session mech key_ in
    let _ = check_ret ret_value C_DecryptInitError false in

    let (ret_value, dec_data_) = Pkcs11.mL_CK_C_Decrypt session todec in
    let _ = check_ret ret_value C_DecryptError false in

    (dec_data_)

(*
let mech_type_to_key_length mech_type = 
  match mech_type with 
  | m when m=Pkcs11.cKM_AES_CBC ->  Pkcs11.int_to_ulong_char_array 16n 
  | m when m=Pkcs11.cKM_DES_CBC -> Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_DES3_CBC -> Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_AES_KEY_GEN -> Pkcs11.int_to_ulong_char_array 16n
  | m when m=Pkcs11.cKM_DES_KEY_GEN ->  Pkcs11.int_to_ulong_char_array 8n
  | m when m=Pkcs11.cKM_DES3_KEY_GEN -> Pkcs11.int_to_ulong_char_array 8n 
  | _ ->  failwith "mech_type_to_key_length : unknown mechanism"
*)
