open P11_common

(* High-level C_FindObjects sequence *)
let find_objects session attrs maxobj =
    let ret_value =  Pkcs11.mL_CK_C_FindObjectsInit session attrs in
    let _ = check_ret ret_value C_FindObjectsInitError false in
    dbg_print !do_verbose "C_FindObjectsInit" ret_value;
    
    let found_ = (
      if compare maxobj Nativeint.minus_one = 0 then
        (* We distinguish the case where we want to find all the objects *)
        let curr_num_ = ref 1n in
        let global_handles_found_ = ref [||] in
        while compare !curr_num_ 0n <> 0 do 
          let (ret_value, curr_found_, curr_count_) =  Pkcs11.mL_CK_C_FindObjects session 1n in
          curr_num_ := curr_count_;
          global_handles_found_ := Array.concat [ !global_handles_found_; curr_found_ ] ;
          let _ = check_ret ret_value C_FindObjectsError false in
          dbg_print !do_verbose "C_FindObjects" ret_value;
        done;
        (!global_handles_found_)
      else
        (* This is the case where we want to find a maximum number of objects *)
        let (ret_value, found_, number_) =  Pkcs11.mL_CK_C_FindObjects session maxobj in
        let _ = check_ret ret_value C_FindObjectsError false in
        dbg_print !do_verbose "C_FindObjects" ret_value;
        (found_)
    ) in
    
    (* Finalize the search session *)
    let ret_value =  Pkcs11.mL_CK_C_FindObjectsFinal session in
    let _ = check_ret ret_value C_FindObjectsFinalError false in
    dbg_print !do_verbose "C_FindObjectsFinal" ret_value;
    (found_, Nativeint.of_int (Array.length found_))

(* High-level C_GetAttributeValue sequence *)
let get_attribute ?continue_on_failure:(cont=false) session_ object_ templ_  =
    let (ret_value, templ_) = Pkcs11.mL_CK_C_GetAttributeValue session_ object_ templ_ in
    let _ = check_ret ret_value C_GetAttributeValueError cont in
    dbg_print !do_verbose "C_GetAttributeValue" ret_value;
    let (ret_value, templ_) = Pkcs11.mL_CK_C_GetAttributeValue session_ object_ templ_ in
    let _ = check_ret ret_value C_GetAttributeValueError cont in
    dbg_print !do_verbose "C_GetAttributeValue" ret_value;
    (ret_value, templ_)

let get_attributes ?continue_on_failure:(cont=false) session_ object_ templ_  =
    (* Split the template *)
    let out_attributes = ref [||] in
    let out_ret_values = ref [||] in 
    let _ = Array.iter (
      fun attr -> 
        let (ret_v, attr_v) = get_attribute ~continue_on_failure:cont session_ object_ [|attr|] in
        out_attributes := Array.concat [!out_attributes; attr_v];
        out_ret_values := Array.concat [!out_ret_values; [|ret_v|]];
    ) templ_ in
    (!out_ret_values, !out_attributes)

(* High-level C_CreateObject *)
let create_cert_object session_ label_ id_ data_ cert_path provided_template = 
    let certclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_CERTIFICATE in
    let certtype = Pkcs11.int_to_ulong_char_array Pkcs11.cKC_X_509 in
    let template = [||] in
    let template = templ_append template Pkcs11.cKA_CLASS certclass in
    let template = templ_append template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_CERTIFICATE_TYPE certtype in
    let template = (
      if compare data_ "" <> 0 then
        let _ = Ssl.init () in
        let mycert  = Ssl.read_certificate cert_path in
        let subject = Ssl.get_subject_asn1 mycert in
        let issuer = Ssl.get_issuer_asn1 mycert in
        let serialnumber = Ssl.get_serialnumber_asn1 mycert in
        let template = templ_append template Pkcs11.cKA_VALUE (Pkcs11.string_to_char_array data_) in
        let template = templ_append template Pkcs11.cKA_SUBJECT subject in
        let template = templ_append template Pkcs11.cKA_ISSUER issuer in
        let template = templ_append template Pkcs11.cKA_SERIAL_NUMBER serialnumber in
        (template)
      else
        (template)
    ) in
    let template = append_some_value_to_template Pkcs11.cKA_LABEL label_ template in
    let template = append_some_value_to_template Pkcs11.cKA_ID id_ template in
    (* Merge the template with the possible one given in *)
    let template = merge_templates template provided_template in

    let (ret_value, handle_) = Pkcs11.mL_CK_C_CreateObject session_ template in
    let _ = check_ret ret_value C_CreateObjectError false in
    dbg_print !do_verbose "C_CreateObject" ret_value;
    (ret_value, handle_)

let create_privkey_object session_ label_ id_ data_ provided_template =
    let keyclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
    let keytype = Pkcs11.int_to_ulong_char_array Pkcs11.cKK_RSA in
    let template = [||] in
    let template = templ_append template Pkcs11.cKA_CLASS keyclass in
    let template = templ_append template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_SIGN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_KEY_TYPE keytype in
    let template = (
      if compare data_ "" <> 0 then
        let _ = Ssl.init () in
        let (modulus, pubexp, privexp, prime1, prime2, exponent1, exponent2, coefficient) = Ssl.get_private_key_asn1 data_ in
        let template = templ_append template Pkcs11.cKA_MODULUS modulus in
        let template = templ_append template Pkcs11.cKA_PUBLIC_EXPONENT pubexp in
        let template = templ_append template Pkcs11.cKA_PRIVATE_EXPONENT privexp in
        let template = templ_append template Pkcs11.cKA_PRIME_1 prime1 in
        let template = templ_append template Pkcs11.cKA_PRIME_2 prime2 in
        let template = templ_append template Pkcs11.cKA_EXPONENT_1 exponent1 in
        let template = templ_append template Pkcs11.cKA_EXPONENT_2 exponent2 in
        let template = templ_append template Pkcs11.cKA_COEFFICIENT coefficient in
        (template)
      else
        (template)
    ) in
    let template = append_some_value_to_template Pkcs11.cKA_LABEL label_ template in
    let template = append_some_value_to_template Pkcs11.cKA_ID id_ template in
    (* Merge the template with the possible one given in *)
    let template = merge_templates template provided_template in

    let (ret_value, handle_) = Pkcs11.mL_CK_C_CreateObject session_ template in
    let _ = check_ret ret_value C_CreateObjectError false in
    dbg_print !do_verbose "C_CreateObject" ret_value;
    (ret_value, handle_)

let create_secretkey_object session_ label_ id_ data_ provided_template =
    let keyclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY in
    let template = [||] in
    let template = templ_append template Pkcs11.cKA_CLASS keyclass in
    let template = templ_append template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_ENCRYPT Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
    let template = (
      if compare data_ "" <> 0 then
        let template = templ_append template Pkcs11.cKA_VALUE (Pkcs11.string_to_char_array data_) in
        (template)
      else
        (template)
    ) in
    let template = append_some_value_to_template Pkcs11.cKA_LABEL label_ template in
    let template = append_some_value_to_template Pkcs11.cKA_ID id_ template in
    (* Merge the template with the possible one given in *)
    let template = merge_templates template provided_template in

    let (ret_value, handle_) = Pkcs11.mL_CK_C_CreateObject session_ template in
    let _ = check_ret ret_value C_CreateObjectError false in
    dbg_print !do_verbose "C_CreateObject" ret_value;
    (ret_value, handle_)



let create_pubkey_object session_ label_ id_ data_ provided_template =
    let keyclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let keytype = Pkcs11.int_to_ulong_char_array Pkcs11.cKK_RSA in
    let template = [||] in
    let template = templ_append template Pkcs11.cKA_CLASS keyclass in
    let template = templ_append template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_VERIFY Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_KEY_TYPE keytype in 
    let template = (
      if compare data_ "" <> 0 then
        let _ = Ssl.init () in
        let (modulus, pubexp) = Ssl.get_public_key_asn1 data_ in
       let template = templ_append template Pkcs11.cKA_MODULUS modulus in
        let template = templ_append template Pkcs11.cKA_PUBLIC_EXPONENT pubexp in
        (template)
      else
        (template)
    ) in
    let template = append_some_value_to_template Pkcs11.cKA_LABEL label_ template in
    let template = append_some_value_to_template Pkcs11.cKA_ID id_ template in
    (* Merge the template with the possible one given in *)
    let template = merge_templates template provided_template in

    let (ret_value, handle_) = Pkcs11.mL_CK_C_CreateObject session_ template in
    let _ = check_ret ret_value C_CreateObjectError false in
    dbg_print !do_verbose "C_CreateObject" ret_value;
    (ret_value, handle_)

(* High-level C_DestroyObject, based on label *)
let destroy_object session_ handle_ =
    let ret_value = Pkcs11.mL_CK_C_DestroyObject session_ handle_ in
    let _ = check_ret ret_value C_DestroyObjectError false in
    dbg_print !do_verbose "C_DestroyObject" ret_value;
    ()

(* High-level C_DestroyObject, based on label, at most max_objects destroyed *)
let destroy_object_with_label label =
    let (ret_value, session_) = Pkcs11.mL_CK_C_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let _ = check_ret ret_value C_OpenSessionError false in
    dbg_print !do_verbose "C_OpenSession" ret_value;

    let templ = [||] in
    let templ = templ_append templ Pkcs11.cKA_LABEL (Pkcs11.string_to_char_array label) in

    let (objects_, count_) =  find_objects session_ templ !max_objects in
    if (compare count_ 0n = 0) then
      begin
        Printf.printf "No objects found, nothing to destroy\n";
      end
    else
      begin
        Array.iter (destroy_object session_ ) objects_;
      end;
    ()

(* High-level C_DestroyObject, based on template, at most max_objects destroyed *)
let destroy_object_with_template provided_template =
    let (ret_value, session_) = Pkcs11.mL_CK_C_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let _ = check_ret ret_value C_OpenSessionError false in
    dbg_print !do_verbose "C_OpenSession" ret_value;

    let (objects_, count_) =  find_objects session_ provided_template !max_objects in
    if (compare count_ 0n = 0) then
      begin
        Printf.printf "No objects found, nothing to destroy\n";
      end
    else
      begin
        Array.iter (destroy_object session_ ) objects_;
      end;
    ()


(* High-level C_DestroyObject, ALL objects destroyed, at most max_objects destroyed *)
let destroy_all_objects _ =
    let (ret_value, session_) = Pkcs11.mL_CK_C_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
    let _ = check_ret ret_value C_OpenSessionError false in
    dbg_print !do_verbose "C_OpenSession" ret_value;

    let (objects_, count_) =  find_objects session_ [||] !max_objects in
    if (compare count_ 0n = 0) then
      begin
        Printf.printf "No objects found, nothing to destroy\n";
      end
    else
      begin
        Array.iter (destroy_object session_ ) objects_;
      end;
    ()


(* High level SetAttributeValue *)
let match_string_to_keygenpair_mech_value in_string =
  match in_string with
| "CKM_RSA_PKCS_KEY_PAIR_GEN" -> Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN
| "CKM_RSA_X9_31_KEY_PAIR_GEN" -> Pkcs11.cKM_RSA_X9_31_KEY_PAIR_GEN
| "CKM_DSA_KEY_PAIR_GEN" -> Pkcs11.cKM_DSA_KEY_PAIR_GEN
| "CKM_DH_PKCS_KEY_PAIR_GEN" -> Pkcs11.cKM_DH_PKCS_KEY_PAIR_GEN
| "CKM_X9_42_DH_KEY_PAIR_GEN" -> Pkcs11.cKM_X9_42_DH_KEY_PAIR_GEN
| "CKM_KEA_KEY_PAIR_GEN" -> Pkcs11.cKM_KEA_KEY_PAIR_GEN
| "CKM_ECDSA_KEY_PAIR_GEN" -> Pkcs11.cKM_ECDSA_KEY_PAIR_GEN
| "CKM_EC_KEY_PAIR_GEN" -> Pkcs11.cKM_EC_KEY_PAIR_GEN
| "CKM_VENDOR_DEFINED" -> Pkcs11.cKM_VENDOR_DEFINED
| _ -> let s = Printf.sprintf "Unknown PKCS#11 key pair generation mechanism %s" in_string in failwith(s)

let match_string_to_sym_key_gen_mech_value in_string =
  match in_string with
| "CKM_RC2_KEY_GEN" -> Pkcs11.cKM_RC2_KEY_GEN
| "CKM_RC4_KEY_GEN" -> Pkcs11.cKM_RC4_KEY_GEN
| "CKM_DES_KEY_GEN" -> Pkcs11.cKM_DES_KEY_GEN
| "CKM_DES2_KEY_GEN" -> Pkcs11.cKM_DES2_KEY_GEN
| "CKM_DES3_KEY_GEN" -> Pkcs11.cKM_DES3_KEY_GEN
| "CKM_CDMF_KEY_GEN" -> Pkcs11.cKM_CDMF_KEY_GEN
| "CKM_CAST_KEY_GEN" -> Pkcs11.cKM_CAST_KEY_GEN
| "CKM_CAST3_KEY_GEN" -> Pkcs11.cKM_CAST3_KEY_GEN
| "CKM_CAST5_KEY_GEN" -> Pkcs11.cKM_CAST5_KEY_GEN
| "CKM_RC5_KEY_GEN" -> Pkcs11.cKM_RC5_KEY_GEN
| "CKM_IDEA_KEY_GEN" -> Pkcs11.cKM_IDEA_KEY_GEN
| "CKM_GENERIC_SECRET_KEY_GEN" -> Pkcs11.cKM_GENERIC_SECRET_KEY_GEN
| "CKM_SSL3_PRE_MASTER_KEY_GEN" -> Pkcs11.cKM_SSL3_PRE_MASTER_KEY_GEN
| "CKM_TLS_PRE_MASTER_KEY_GEN" -> Pkcs11.cKM_TLS_PRE_MASTER_KEY_GEN
| "CKM_PBE_MD2_DES_CBC" -> Pkcs11.cKM_PBE_MD2_DES_CBC
| "CKM_PBE_MD5_DES_CBC" -> Pkcs11.cKM_PBE_MD5_DES_CBC
| "CKM_PBE_MD5_CAST_CBC" -> Pkcs11.cKM_PBE_MD5_CAST_CBC
| "CKM_PBE_MD5_CAST3_CBC" -> Pkcs11.cKM_PBE_MD5_CAST3_CBC
| "CKM_PBE_MD5_CAST5_CBC" -> Pkcs11.cKM_PBE_MD5_CAST5_CBC
| "CKM_PBE_SHA1_CAST5_CBC" -> Pkcs11.cKM_PBE_SHA1_CAST5_CBC
| "CKM_PBE_SHA1_RC4_128" -> Pkcs11.cKM_PBE_SHA1_RC4_128
| "CKM_PBE_SHA1_RC4_40" -> Pkcs11.cKM_PBE_SHA1_RC4_40
| "CKM_PBE_SHA1_DES3_EDE_CBC" -> Pkcs11.cKM_PBE_SHA1_DES3_EDE_CBC
| "CKM_PBE_SHA1_DES2_EDE_CBC" -> Pkcs11.cKM_PBE_SHA1_DES2_EDE_CBC
| "CKM_PBE_SHA1_RC2_128_CBC" -> Pkcs11.cKM_PBE_SHA1_RC2_128_CBC
| "CKM_PBE_SHA1_RC2_40_CBC" -> Pkcs11.cKM_PBE_SHA1_RC2_40_CBC
| "CKM_PKCS5_PBKD2" -> Pkcs11.cKM_PKCS5_PBKD2
| "CKM_PBA_SHA1_WITH_SHA1_HMAC" -> Pkcs11.cKM_PBA_SHA1_WITH_SHA1_HMAC
| "CKM_SKIPJACK_KEY_GEN" -> Pkcs11.cKM_SKIPJACK_KEY_GEN
| "CKM_BATON_KEY_GEN" -> Pkcs11.cKM_BATON_KEY_GEN
| "CKM_JUNIPER_KEY_GEN" -> Pkcs11.cKM_JUNIPER_KEY_GEN
| "CKM_AES_KEY_GEN" -> Pkcs11.cKM_AES_KEY_GEN
| "CKM_VENDOR_DEFINED" -> Pkcs11.cKM_VENDOR_DEFINED
| _ -> let s = Printf.sprintf "Unknown PKCS#11 symetric key generation mechanism %s" in_string in failwith(s)


(* Matching string on PKCS#11 values *)
let match_string_to_p11_value in_string =
  match in_string with
  (* Try to match a PKCS#11 value *)
  (* Mechanisms *)
| "CKM_RSA_PKCS_KEY_PAIR_GEN" -> Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN
| "CKM_RSA_PKCS" -> Pkcs11.cKM_RSA_PKCS
| "CKM_RSA_9796" -> Pkcs11.cKM_RSA_9796
| "CKM_RSA_X_509" -> Pkcs11.cKM_RSA_X_509
| "CKM_MD2_RSA_PKCS" -> Pkcs11.cKM_MD2_RSA_PKCS
| "CKM_MD5_RSA_PKCS" -> Pkcs11.cKM_MD5_RSA_PKCS
| "CKM_SHA1_RSA_PKCS" -> Pkcs11.cKM_SHA1_RSA_PKCS
| "CKM_RIPEMD128_RSA_PKCS" -> Pkcs11.cKM_RIPEMD128_RSA_PKCS
| "CKM_RIPEMD160_RSA_PKCS" -> Pkcs11.cKM_RIPEMD160_RSA_PKCS
| "CKM_RSA_PKCS_OAEP" -> Pkcs11.cKM_RSA_PKCS_OAEP
| "CKM_RSA_X9_31_KEY_PAIR_GEN" -> Pkcs11.cKM_RSA_X9_31_KEY_PAIR_GEN
| "CKM_RSA_X9_31" -> Pkcs11.cKM_RSA_X9_31
| "CKM_SHA1_RSA_X9_31" -> Pkcs11.cKM_SHA1_RSA_X9_31
| "CKM_RSA_PKCS_PSS" -> Pkcs11.cKM_RSA_PKCS_PSS
| "CKM_SHA1_RSA_PKCS_PSS" -> Pkcs11.cKM_SHA1_RSA_PKCS_PSS
| "CKM_DSA_KEY_PAIR_GEN" -> Pkcs11.cKM_DSA_KEY_PAIR_GEN
| "CKM_DSA" -> Pkcs11.cKM_DSA
| "CKM_DSA_SHA1" -> Pkcs11.cKM_DSA_SHA1
| "CKM_DH_PKCS_KEY_PAIR_GEN" -> Pkcs11.cKM_DH_PKCS_KEY_PAIR_GEN
| "CKM_DH_PKCS_DERIVE" -> Pkcs11.cKM_DH_PKCS_DERIVE
| "CKM_X9_42_DH_KEY_PAIR_GEN" -> Pkcs11.cKM_X9_42_DH_KEY_PAIR_GEN
| "CKM_X9_42_DH_DERIVE" -> Pkcs11.cKM_X9_42_DH_DERIVE
| "CKM_X9_42_DH_HYBRID_DERIVE" -> Pkcs11.cKM_X9_42_DH_HYBRID_DERIVE
| "CKM_X9_42_MQV_DERIVE" -> Pkcs11.cKM_X9_42_MQV_DERIVE
| "CKM_SHA256_RSA_PKCS" -> Pkcs11.cKM_SHA256_RSA_PKCS
| "CKM_SHA384_RSA_PKCS" -> Pkcs11.cKM_SHA384_RSA_PKCS
| "CKM_SHA512_RSA_PKCS" -> Pkcs11.cKM_SHA512_RSA_PKCS
| "CKM_SHA224_RSA_PKCS" -> Pkcs11.cKM_SHA224_RSA_PKCS
| "CKM_SHA256_RSA_PKCS_PSS" -> Pkcs11.cKM_SHA256_RSA_PKCS_PSS
| "CKM_SHA384_RSA_PKCS_PSS" -> Pkcs11.cKM_SHA384_RSA_PKCS_PSS
| "CKM_SHA512_RSA_PKCS_PSS" -> Pkcs11.cKM_SHA512_RSA_PKCS_PSS
| "CKM_SHA224_RSA_PKCS_PSS" -> Pkcs11.cKM_SHA224_RSA_PKCS_PSS
| "CKM_RC2_KEY_GEN" -> Pkcs11.cKM_RC2_KEY_GEN
| "CKM_RC2_ECB" -> Pkcs11.cKM_RC2_ECB
| "CKM_RC2_CBC" -> Pkcs11.cKM_RC2_CBC
| "CKM_RC2_MAC" -> Pkcs11.cKM_RC2_MAC
| "CKM_RC2_MAC_GENERAL" -> Pkcs11.cKM_RC2_MAC_GENERAL
| "CKM_RC2_CBC_PAD" -> Pkcs11.cKM_RC2_CBC_PAD
| "CKM_RC4_KEY_GEN" -> Pkcs11.cKM_RC4_KEY_GEN
| "CKM_RC4" -> Pkcs11.cKM_RC4
| "CKM_DES_KEY_GEN" -> Pkcs11.cKM_DES_KEY_GEN
| "CKM_DES_ECB" -> Pkcs11.cKM_DES_ECB
| "CKM_DES_CBC" -> Pkcs11.cKM_DES_CBC
| "CKM_DES_MAC" -> Pkcs11.cKM_DES_MAC
| "CKM_DES_MAC_GENERAL" -> Pkcs11.cKM_DES_MAC_GENERAL
| "CKM_DES_CBC_PAD" -> Pkcs11.cKM_DES_CBC_PAD
| "CKM_DES2_KEY_GEN" -> Pkcs11.cKM_DES2_KEY_GEN
| "CKM_DES3_KEY_GEN" -> Pkcs11.cKM_DES3_KEY_GEN
| "CKM_DES3_ECB" -> Pkcs11.cKM_DES3_ECB
| "CKM_DES3_CBC" -> Pkcs11.cKM_DES3_CBC
| "CKM_DES3_MAC" -> Pkcs11.cKM_DES3_MAC
| "CKM_DES3_MAC_GENERAL" -> Pkcs11.cKM_DES3_MAC_GENERAL
| "CKM_DES3_CBC_PAD" -> Pkcs11.cKM_DES3_CBC_PAD
| "CKM_CDMF_KEY_GEN" -> Pkcs11.cKM_CDMF_KEY_GEN
| "CKM_CDMF_ECB" -> Pkcs11.cKM_CDMF_ECB
| "CKM_CDMF_CBC" -> Pkcs11.cKM_CDMF_CBC
| "CKM_CDMF_MAC" -> Pkcs11.cKM_CDMF_MAC
| "CKM_CDMF_MAC_GENERAL" -> Pkcs11.cKM_CDMF_MAC_GENERAL
| "CKM_CDMF_CBC_PAD" -> Pkcs11.cKM_CDMF_CBC_PAD
| "CKM_MD2" -> Pkcs11.cKM_MD2
| "CKM_MD2_HMAC" -> Pkcs11.cKM_MD2_HMAC
| "CKM_MD2_HMAC_GENERAL" -> Pkcs11.cKM_MD2_HMAC_GENERAL
| "CKM_MD5" -> Pkcs11.cKM_MD5
| "CKM_MD5_HMAC" -> Pkcs11.cKM_MD5_HMAC
| "CKM_MD5_HMAC_GENERAL" -> Pkcs11.cKM_MD5_HMAC_GENERAL
| "CKM_SHA_1" -> Pkcs11.cKM_SHA_1
| "CKM_SHA_1_HMAC" -> Pkcs11.cKM_SHA_1_HMAC
| "CKM_SHA_1_HMAC_GENERAL" -> Pkcs11.cKM_SHA_1_HMAC_GENERAL
| "CKM_RIPEMD128" -> Pkcs11.cKM_RIPEMD128
| "CKM_RIPEMD128_HMAC" -> Pkcs11.cKM_RIPEMD128_HMAC
| "CKM_RIPEMD128_HMAC_GENERAL" -> Pkcs11.cKM_RIPEMD128_HMAC_GENERAL
| "CKM_RIPEMD160" -> Pkcs11.cKM_RIPEMD160
| "CKM_RIPEMD160_HMAC" -> Pkcs11.cKM_RIPEMD160_HMAC
| "CKM_RIPEMD160_HMAC_GENERAL" -> Pkcs11.cKM_RIPEMD160_HMAC_GENERAL
| "CKM_SHA256" -> Pkcs11.cKM_SHA256
| "CKM_SHA256_HMAC" -> Pkcs11.cKM_SHA256_HMAC
| "CKM_SHA256_HMAC_GENERAL" -> Pkcs11.cKM_SHA256_HMAC_GENERAL
| "CKM_SHA224" -> Pkcs11.cKM_SHA224
| "CKM_SHA224_HMAC" -> Pkcs11.cKM_SHA224_HMAC
| "CKM_SHA224_HMAC_GENERAL" -> Pkcs11.cKM_SHA224_HMAC_GENERAL
| "CKM_SHA384" -> Pkcs11.cKM_SHA384
| "CKM_SHA384_HMAC" -> Pkcs11.cKM_SHA384_HMAC
| "CKM_SHA384_HMAC_GENERAL" -> Pkcs11.cKM_SHA384_HMAC_GENERAL
| "CKM_SHA512" -> Pkcs11.cKM_SHA512
| "CKM_SHA512_HMAC" -> Pkcs11.cKM_SHA512_HMAC
| "CKM_SHA512_HMAC_GENERAL" -> Pkcs11.cKM_SHA512_HMAC_GENERAL
| "CKM_SECURID_KEY_GEN" -> Pkcs11.cKM_SECURID_KEY_GEN
| "CKM_SECURID" -> Pkcs11.cKM_SECURID
| "CKM_HOTP_KEY_GEN" -> Pkcs11.cKM_HOTP_KEY_GEN
| "CKM_HOTP" -> Pkcs11.cKM_HOTP
| "CKM_ACTI_KEY_GEN" -> Pkcs11.cKM_ACTI_KEY_GEN
| "CKM_ACTI" -> Pkcs11.cKM_ACTI
| "CKM_CAST_KEY_GEN" -> Pkcs11.cKM_CAST_KEY_GEN
| "CKM_CAST_ECB" -> Pkcs11.cKM_CAST_ECB
| "CKM_CAST_CBC" -> Pkcs11.cKM_CAST_CBC
| "CKM_CAST_MAC" -> Pkcs11.cKM_CAST_MAC
| "CKM_CAST_MAC_GENERAL" -> Pkcs11.cKM_CAST_MAC_GENERAL
| "CKM_CAST_CBC_PAD" -> Pkcs11.cKM_CAST_CBC_PAD
| "CKM_CAST3_KEY_GEN" -> Pkcs11.cKM_CAST3_KEY_GEN
| "CKM_CAST3_ECB" -> Pkcs11.cKM_CAST3_ECB
| "CKM_CAST3_CBC" -> Pkcs11.cKM_CAST3_CBC
| "CKM_CAST3_MAC" -> Pkcs11.cKM_CAST3_MAC
| "CKM_CAST3_MAC_GENERAL" -> Pkcs11.cKM_CAST3_MAC_GENERAL
| "CKM_CAST3_CBC_PAD" -> Pkcs11.cKM_CAST3_CBC_PAD
| "CKM_CAST5_KEY_GEN" -> Pkcs11.cKM_CAST5_KEY_GEN
| "CKM_CAST5_ECB" -> Pkcs11.cKM_CAST5_ECB
| "CKM_CAST5_CBC" -> Pkcs11.cKM_CAST5_CBC
| "CKM_CAST5_MAC" -> Pkcs11.cKM_CAST5_MAC
| "CKM_CAST5_MAC_GENERAL" -> Pkcs11.cKM_CAST5_MAC_GENERAL
| "CKM_CAST5_CBC_PAD" -> Pkcs11.cKM_CAST5_CBC_PAD
| "CKM_RC5_KEY_GEN" -> Pkcs11.cKM_RC5_KEY_GEN
| "CKM_RC5_ECB" -> Pkcs11.cKM_RC5_ECB
| "CKM_RC5_CBC" -> Pkcs11.cKM_RC5_CBC
| "CKM_RC5_MAC" -> Pkcs11.cKM_RC5_MAC
| "CKM_RC5_MAC_GENERAL" -> Pkcs11.cKM_RC5_MAC_GENERAL
| "CKM_RC5_CBC_PAD" -> Pkcs11.cKM_RC5_CBC_PAD
| "CKM_IDEA_KEY_GEN" -> Pkcs11.cKM_IDEA_KEY_GEN
| "CKM_IDEA_ECB" -> Pkcs11.cKM_IDEA_ECB
| "CKM_IDEA_CBC" -> Pkcs11.cKM_IDEA_CBC
| "CKM_IDEA_MAC" -> Pkcs11.cKM_IDEA_MAC
| "CKM_IDEA_MAC_GENERAL" -> Pkcs11.cKM_IDEA_MAC_GENERAL
| "CKM_IDEA_CBC_PAD" -> Pkcs11.cKM_IDEA_CBC_PAD
| "CKM_GENERIC_SECRET_KEY_GEN" -> Pkcs11.cKM_GENERIC_SECRET_KEY_GEN
| "CKM_CONCATENATE_BASE_AND_KEY" -> Pkcs11.cKM_CONCATENATE_BASE_AND_KEY
| "CKM_CONCATENATE_BASE_AND_DATA" -> Pkcs11.cKM_CONCATENATE_BASE_AND_DATA
| "CKM_CONCATENATE_DATA_AND_BASE" -> Pkcs11.cKM_CONCATENATE_DATA_AND_BASE
| "CKM_XOR_BASE_AND_DATA" -> Pkcs11.cKM_XOR_BASE_AND_DATA
| "CKM_EXTRACT_KEY_FROM_KEY" -> Pkcs11.cKM_EXTRACT_KEY_FROM_KEY
| "CKM_SSL3_PRE_MASTER_KEY_GEN" -> Pkcs11.cKM_SSL3_PRE_MASTER_KEY_GEN
| "CKM_SSL3_MASTER_KEY_DERIVE" -> Pkcs11.cKM_SSL3_MASTER_KEY_DERIVE
| "CKM_SSL3_KEY_AND_MAC_DERIVE" -> Pkcs11.cKM_SSL3_KEY_AND_MAC_DERIVE
| "CKM_SSL3_MASTER_KEY_DERIVE_DH" -> Pkcs11.cKM_SSL3_MASTER_KEY_DERIVE_DH
| "CKM_TLS_PRE_MASTER_KEY_GEN" -> Pkcs11.cKM_TLS_PRE_MASTER_KEY_GEN
| "CKM_TLS_MASTER_KEY_DERIVE" -> Pkcs11.cKM_TLS_MASTER_KEY_DERIVE
| "CKM_TLS_KEY_AND_MAC_DERIVE" -> Pkcs11.cKM_TLS_KEY_AND_MAC_DERIVE
| "CKM_TLS_MASTER_KEY_DERIVE_DH" -> Pkcs11.cKM_TLS_MASTER_KEY_DERIVE_DH
| "CKM_TLS_PRF" -> Pkcs11.cKM_TLS_PRF
| "CKM_SSL3_MD5_MAC" -> Pkcs11.cKM_SSL3_MD5_MAC
| "CKM_SSL3_SHA1_MAC" -> Pkcs11.cKM_SSL3_SHA1_MAC
| "CKM_MD5_KEY_DERIVATION" -> Pkcs11.cKM_MD5_KEY_DERIVATION
| "CKM_MD2_KEY_DERIVATION" -> Pkcs11.cKM_MD2_KEY_DERIVATION
| "CKM_SHA1_KEY_DERIVATION" -> Pkcs11.cKM_SHA1_KEY_DERIVATION
| "CKM_SHA256_KEY_DERIVATION" -> Pkcs11.cKM_SHA256_KEY_DERIVATION
| "CKM_SHA384_KEY_DERIVATION" -> Pkcs11.cKM_SHA384_KEY_DERIVATION
| "CKM_SHA512_KEY_DERIVATION" -> Pkcs11.cKM_SHA512_KEY_DERIVATION
| "CKM_SHA224_KEY_DERIVATION" -> Pkcs11.cKM_SHA224_KEY_DERIVATION
| "CKM_PBE_MD2_DES_CBC" -> Pkcs11.cKM_PBE_MD2_DES_CBC
| "CKM_PBE_MD5_DES_CBC" -> Pkcs11.cKM_PBE_MD5_DES_CBC
| "CKM_PBE_MD5_CAST_CBC" -> Pkcs11.cKM_PBE_MD5_CAST_CBC
| "CKM_PBE_MD5_CAST3_CBC" -> Pkcs11.cKM_PBE_MD5_CAST3_CBC
| "CKM_PBE_MD5_CAST5_CBC" -> Pkcs11.cKM_PBE_MD5_CAST5_CBC
| "CKM_PBE_SHA1_CAST5_CBC" -> Pkcs11.cKM_PBE_SHA1_CAST5_CBC
| "CKM_PBE_SHA1_RC4_128" -> Pkcs11.cKM_PBE_SHA1_RC4_128
| "CKM_PBE_SHA1_RC4_40" -> Pkcs11.cKM_PBE_SHA1_RC4_40
| "CKM_PBE_SHA1_DES3_EDE_CBC" -> Pkcs11.cKM_PBE_SHA1_DES3_EDE_CBC
| "CKM_PBE_SHA1_DES2_EDE_CBC" -> Pkcs11.cKM_PBE_SHA1_DES2_EDE_CBC
| "CKM_PBE_SHA1_RC2_128_CBC" -> Pkcs11.cKM_PBE_SHA1_RC2_128_CBC
| "CKM_PBE_SHA1_RC2_40_CBC" -> Pkcs11.cKM_PBE_SHA1_RC2_40_CBC
| "CKM_PKCS5_PBKD2" -> Pkcs11.cKM_PKCS5_PBKD2
| "CKM_PBA_SHA1_WITH_SHA1_HMAC" -> Pkcs11.cKM_PBA_SHA1_WITH_SHA1_HMAC
| "CKM_WTLS_PRE_MASTER_KEY_GEN" -> Pkcs11.cKM_WTLS_PRE_MASTER_KEY_GEN
| "CKM_WTLS_MASTER_KEY_DERIVE" -> Pkcs11.cKM_WTLS_MASTER_KEY_DERIVE
| "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC" -> Pkcs11.cKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
| "CKM_WTLS_PRF" -> Pkcs11.cKM_WTLS_PRF
| "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE" -> Pkcs11.cKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
| "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE" -> Pkcs11.cKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
| "CKM_CMS_SIG" -> Pkcs11.cKM_CMS_SIG
| "CKM_KIP_DERIVE" -> Pkcs11.cKM_KIP_DERIVE
| "CKM_KIP_WRAP" -> Pkcs11.cKM_KIP_WRAP
| "CKM_KIP_MAC" -> Pkcs11.cKM_KIP_MAC
| "CKM_CAMELLIA_KEY_GEN" -> Pkcs11.cKM_CAMELLIA_KEY_GEN
| "CKM_CAMELLIA_ECB" -> Pkcs11.cKM_CAMELLIA_ECB
| "CKM_CAMELLIA_CBC" -> Pkcs11.cKM_CAMELLIA_CBC
| "CKM_CAMELLIA_MAC" -> Pkcs11.cKM_CAMELLIA_MAC
| "CKM_CAMELLIA_MAC_GENERAL" -> Pkcs11.cKM_CAMELLIA_MAC_GENERAL
| "CKM_CAMELLIA_CBC_PAD" -> Pkcs11.cKM_CAMELLIA_CBC_PAD
| "CKM_CAMELLIA_ECB_ENCRYPT_DATA" -> Pkcs11.cKM_CAMELLIA_ECB_ENCRYPT_DATA
| "CKM_CAMELLIA_CBC_ENCRYPT_DATA" -> Pkcs11.cKM_CAMELLIA_CBC_ENCRYPT_DATA
| "CKM_CAMELLIA_CTR" -> Pkcs11.cKM_CAMELLIA_CTR
| "CKM_ARIA_KEY_GEN" -> Pkcs11.cKM_ARIA_KEY_GEN
| "CKM_ARIA_ECB" -> Pkcs11.cKM_ARIA_ECB
| "CKM_ARIA_CBC" -> Pkcs11.cKM_ARIA_CBC
| "CKM_ARIA_MAC" -> Pkcs11.cKM_ARIA_MAC
| "CKM_ARIA_MAC_GENERAL" -> Pkcs11.cKM_ARIA_MAC_GENERAL
| "CKM_ARIA_CBC_PAD" -> Pkcs11.cKM_ARIA_CBC_PAD
| "CKM_ARIA_ECB_ENCRYPT_DATA" -> Pkcs11.cKM_ARIA_ECB_ENCRYPT_DATA
| "CKM_ARIA_CBC_ENCRYPT_DATA" -> Pkcs11.cKM_ARIA_CBC_ENCRYPT_DATA
| "CKM_AES_CTR" -> Pkcs11.cKM_AES_CTR
| "CKM_BLOWFISH_KEY_GEN" -> Pkcs11.cKM_BLOWFISH_KEY_GEN
| "CKM_BLOWFISH_CBC" -> Pkcs11.cKM_BLOWFISH_CBC
| "CKM_TWOFISH_KEY_GEN" -> Pkcs11.cKM_TWOFISH_KEY_GEN
| "CKM_TWOFISH_CBC" -> Pkcs11.cKM_TWOFISH_CBC
| "CKM_DES_ECB_ENCRYPT_DATA" -> Pkcs11.cKM_DES_ECB_ENCRYPT_DATA
| "CKM_DES_CBC_ENCRYPT_DATA" -> Pkcs11.cKM_DES_CBC_ENCRYPT_DATA
| "CKM_DES3_ECB_ENCRYPT_DATA" -> Pkcs11.cKM_DES3_ECB_ENCRYPT_DATA
| "CKM_DES3_CBC_ENCRYPT_DATA" -> Pkcs11.cKM_DES3_CBC_ENCRYPT_DATA
| "CKM_AES_ECB_ENCRYPT_DATA" -> Pkcs11.cKM_AES_ECB_ENCRYPT_DATA
| "CKM_AES_CBC_ENCRYPT_DATA" -> Pkcs11.cKM_AES_CBC_ENCRYPT_DATA
| "CKM_KEY_WRAP_LYNKS" -> Pkcs11.cKM_KEY_WRAP_LYNKS
| "CKM_KEY_WRAP_SET_OAEP" -> Pkcs11.cKM_KEY_WRAP_SET_OAEP
| "CKM_SKIPJACK_KEY_GEN" -> Pkcs11.cKM_SKIPJACK_KEY_GEN
| "CKM_SKIPJACK_ECB64" -> Pkcs11.cKM_SKIPJACK_ECB64
| "CKM_SKIPJACK_CBC64" -> Pkcs11.cKM_SKIPJACK_CBC64
| "CKM_SKIPJACK_OFB64" -> Pkcs11.cKM_SKIPJACK_OFB64
| "CKM_SKIPJACK_CFB64" -> Pkcs11.cKM_SKIPJACK_CFB64
| "CKM_SKIPJACK_CFB32" -> Pkcs11.cKM_SKIPJACK_CFB32
| "CKM_SKIPJACK_CFB16" -> Pkcs11.cKM_SKIPJACK_CFB16
| "CKM_SKIPJACK_CFB8" -> Pkcs11.cKM_SKIPJACK_CFB8
| "CKM_SKIPJACK_WRAP" -> Pkcs11.cKM_SKIPJACK_WRAP
| "CKM_SKIPJACK_PRIVATE_WRAP" -> Pkcs11.cKM_SKIPJACK_PRIVATE_WRAP
| "CKM_SKIPJACK_RELAYX" -> Pkcs11.cKM_SKIPJACK_RELAYX
| "CKM_KEA_KEY_PAIR_GEN" -> Pkcs11.cKM_KEA_KEY_PAIR_GEN
| "CKM_KEA_KEY_DERIVE" -> Pkcs11.cKM_KEA_KEY_DERIVE
| "CKM_FORTEZZA_TIMESTAMP" -> Pkcs11.cKM_FORTEZZA_TIMESTAMP
| "CKM_BATON_KEY_GEN" -> Pkcs11.cKM_BATON_KEY_GEN
| "CKM_BATON_ECB128" -> Pkcs11.cKM_BATON_ECB128
| "CKM_BATON_ECB96" -> Pkcs11.cKM_BATON_ECB96
| "CKM_BATON_CBC128" -> Pkcs11.cKM_BATON_CBC128
| "CKM_BATON_COUNTER" -> Pkcs11.cKM_BATON_COUNTER
| "CKM_BATON_SHUFFLE" -> Pkcs11.cKM_BATON_SHUFFLE
| "CKM_BATON_WRAP" -> Pkcs11.cKM_BATON_WRAP
| "CKM_ECDSA_KEY_PAIR_GEN" -> Pkcs11.cKM_ECDSA_KEY_PAIR_GEN
| "CKM_EC_KEY_PAIR_GEN" -> Pkcs11.cKM_EC_KEY_PAIR_GEN
| "CKM_ECDSA" -> Pkcs11.cKM_ECDSA
| "CKM_ECDSA_SHA1" -> Pkcs11.cKM_ECDSA_SHA1
| "CKM_ECDH1_DERIVE" -> Pkcs11.cKM_ECDH1_DERIVE
| "CKM_ECDH1_COFACTOR_DERIVE" -> Pkcs11.cKM_ECDH1_COFACTOR_DERIVE
| "CKM_ECMQV_DERIVE" -> Pkcs11.cKM_ECMQV_DERIVE
| "CKM_JUNIPER_KEY_GEN" -> Pkcs11.cKM_JUNIPER_KEY_GEN
| "CKM_JUNIPER_ECB128" -> Pkcs11.cKM_JUNIPER_ECB128
| "CKM_JUNIPER_CBC128" -> Pkcs11.cKM_JUNIPER_CBC128
| "CKM_JUNIPER_COUNTER" -> Pkcs11.cKM_JUNIPER_COUNTER
| "CKM_JUNIPER_SHUFFLE" -> Pkcs11.cKM_JUNIPER_SHUFFLE
| "CKM_JUNIPER_WRAP" -> Pkcs11.cKM_JUNIPER_WRAP
| "CKM_FASTHASH" -> Pkcs11.cKM_FASTHASH
| "CKM_AES_KEY_GEN" -> Pkcs11.cKM_AES_KEY_GEN
| "CKM_AES_ECB" -> Pkcs11.cKM_AES_ECB
| "CKM_AES_CBC" -> Pkcs11.cKM_AES_CBC
| "CKM_AES_MAC" -> Pkcs11.cKM_AES_MAC
| "CKM_AES_MAC_GENERAL" -> Pkcs11.cKM_AES_MAC_GENERAL
| "CKM_AES_CBC_PAD" -> Pkcs11.cKM_AES_CBC_PAD
| "CKM_DSA_PARAMETER_GEN" -> Pkcs11.cKM_DSA_PARAMETER_GEN
| "CKM_DH_PKCS_PARAMETER_GEN" -> Pkcs11.cKM_DH_PKCS_PARAMETER_GEN
| "CKM_X9_42_DH_PARAMETER_GEN" -> Pkcs11.cKM_X9_42_DH_PARAMETER_GEN
| "CKM_VENDOR_DEFINED" -> Pkcs11.cKM_VENDOR_DEFINED
  (* Functions *)
| "CKF_TOKEN_PRESENT" -> Pkcs11.cKF_TOKEN_PRESENT
| "CKF_RNG" -> Pkcs11.cKF_RNG
| "CKF_HW" -> Pkcs11.cKF_HW
| "CKF_DONT_BLOCK" -> Pkcs11.cKF_DONT_BLOCK
| "CKF_LIBRARY_CANT_CREATE_OS_THREADS" -> Pkcs11.cKF_LIBRARY_CANT_CREATE_OS_THREADS
| "CKF_REMOVABLE_DEVICE" -> Pkcs11.cKF_REMOVABLE_DEVICE
| "CKF_RW_SESSION" -> Pkcs11.cKF_RW_SESSION
| "CKF_WRITE_PROTECTED" -> Pkcs11.cKF_WRITE_PROTECTED
| "CKF_OS_LOCKING_OK" -> Pkcs11.cKF_OS_LOCKING_OK
| "CKF_HW_SLOT" -> Pkcs11.cKF_HW_SLOT
| "CKF_LOGIN_REQUIRED" -> Pkcs11.cKF_LOGIN_REQUIRED
| "CKF_SERIAL_SESSION" -> Pkcs11.cKF_SERIAL_SESSION
| "CKF_ARRAY_ATTRIBUTE" -> Pkcs11.cKF_ARRAY_ATTRIBUTE
| "CKF_USER_PIN_INITIALIZED" -> Pkcs11.cKF_USER_PIN_INITIALIZED
| "CKF_RESTORE_KEY_NOT_NEEDED" -> Pkcs11.cKF_RESTORE_KEY_NOT_NEEDED
| "CKF_CLOCK_ON_TOKEN" -> Pkcs11.cKF_CLOCK_ON_TOKEN
| "CKF_PROTECTED_AUTHENTICATION_PATH" -> Pkcs11.cKF_PROTECTED_AUTHENTICATION_PATH
| "CKF_ENCRYPT" -> Pkcs11.cKF_ENCRYPT
| "CKF_DUAL_CRYPTO_OPERATIONS" -> Pkcs11.cKF_DUAL_CRYPTO_OPERATIONS
| "CKF_DECRYPT" -> Pkcs11.cKF_DECRYPT
| "CKF_TOKEN_INITIALIZED" -> Pkcs11.cKF_TOKEN_INITIALIZED
| "CKF_DIGEST" -> Pkcs11.cKF_DIGEST
| "CKF_SECONDARY_AUTHENTICATION" -> Pkcs11.cKF_SECONDARY_AUTHENTICATION
| "CKF_SIGN" -> Pkcs11.cKF_SIGN
| "CKF_USER_PIN_COUNT_LOW" -> Pkcs11.cKF_USER_PIN_COUNT_LOW
| "CKF_GENERATE_KEY_PAIR" -> Pkcs11.cKF_GENERATE_KEY_PAIR
| "CKF_USER_PIN_FINAL_TRY" -> Pkcs11.cKF_USER_PIN_FINAL_TRY
| "CKF_WRAP" -> Pkcs11.cKF_WRAP
| "CKF_USER_PIN_LOCKED" -> Pkcs11.cKF_USER_PIN_LOCKED
| "CKF_UNWRAP" -> Pkcs11.cKF_UNWRAP
| "CKF_USER_PIN_TO_BE_CHANGED" -> Pkcs11.cKF_USER_PIN_TO_BE_CHANGED
| "CKF_DERIVE" -> Pkcs11.cKF_DERIVE
| "CKF_EC_F_P" -> Pkcs11.cKF_EC_F_P
| "CKF_EC_F_2M" -> Pkcs11.cKF_EC_F_2M
| "CKF_EC_ECPARAMETERS" -> Pkcs11.cKF_EC_ECPARAMETERS
| "CKF_EC_NAMEDCURVE" -> Pkcs11.cKF_EC_NAMEDCURVE
| "CKF_EC_UNCOMPRESS" -> Pkcs11.cKF_EC_UNCOMPRESS
| "CKF_EC_COMPRESS" -> Pkcs11.cKF_EC_COMPRESS
| "CKF_SO_PIN_COUNT_LOW" -> Pkcs11.cKF_SO_PIN_COUNT_LOW
| "CKF_SO_PIN_FINAL_TRY" -> Pkcs11.cKF_SO_PIN_FINAL_TRY
| "CKF_SO_PIN_LOCKED" -> Pkcs11.cKF_SO_PIN_LOCKED
| "CKF_SO_PIN_TO_BE_CHANGED" -> Pkcs11.cKF_SO_PIN_TO_BE_CHANGED
| "CKF_SIGN_RECOVER" -> Pkcs11.cKF_SIGN_RECOVER
| "CKF_VERIFY" -> Pkcs11.cKF_VERIFY
| "CKF_VERIFY_RECOVER" -> Pkcs11.cKF_VERIFY_RECOVER
| "CKF_GENERATE" -> Pkcs11.cKF_GENERATE
| "CKF_EXTENSION" -> Pkcs11.cKF_EXTENSION
  (* Objects *) 
| "CKO_DATA" -> Pkcs11.cKO_DATA
| "CKO_CERTIFICATE" -> Pkcs11.cKO_CERTIFICATE
| "CKO_PUBLIC_KEY" -> Pkcs11.cKO_PUBLIC_KEY
| "CKO_PRIVATE_KEY" -> Pkcs11.cKO_PRIVATE_KEY
| "CKO_SECRET_KEY" -> Pkcs11.cKO_SECRET_KEY
| "CKO_HW_FEATURE" -> Pkcs11.cKO_HW_FEATURE
| "CKO_DOMAIN_PARAMETERS" -> Pkcs11.cKO_DOMAIN_PARAMETERS
| "CKO_MECHANISM" -> Pkcs11.cKO_MECHANISM
| "CKO_VENDOR_DEFINED" -> Pkcs11.cKO_VENDOR_DEFINED
  (* User *)
| "CKU_SO" -> Pkcs11.cKU_SO
| "CKU_USER" -> Pkcs11.cKU_USER
| "CKU_CONTEXT_SPECIFIC" -> Pkcs11.cKU_CONTEXT_SPECIFIC
  (* Attributes *)
| "CKA_CLASS" -> Pkcs11.cKA_CLASS
| "CKA_TOKEN" -> Pkcs11.cKA_TOKEN
| "CKA_PRIVATE" -> Pkcs11.cKA_PRIVATE
| "CKA_LABEL" -> Pkcs11.cKA_LABEL
| "CKA_APPLICATION" -> Pkcs11.cKA_APPLICATION
| "CKA_VALUE" -> Pkcs11.cKA_VALUE
| "CKA_OBJECT_ID" -> Pkcs11.cKA_OBJECT_ID
| "CKA_CERTIFICATE_TYPE" -> Pkcs11.cKA_CERTIFICATE_TYPE
| "CKA_ISSUER" -> Pkcs11.cKA_ISSUER
| "CKA_SERIAL_NUMBER" -> Pkcs11.cKA_SERIAL_NUMBER
| "CKA_AC_ISSUER" -> Pkcs11.cKA_AC_ISSUER
| "CKA_OWNER" -> Pkcs11.cKA_OWNER
| "CKA_ATTR_TYPES" -> Pkcs11.cKA_ATTR_TYPES
| "CKA_TRUSTED" -> Pkcs11.cKA_TRUSTED
| "CKA_CERTIFICATE_CATEGORY" -> Pkcs11.cKA_CERTIFICATE_CATEGORY
| "CKA_JAVA_MIDP_SECURITY_DOMAIN" -> Pkcs11.cKA_JAVA_MIDP_SECURITY_DOMAIN
| "CKA_URL" -> Pkcs11.cKA_URL
| "CKA_HASH_OF_SUBJECT_PUBLIC_KEY" -> Pkcs11.cKA_HASH_OF_SUBJECT_PUBLIC_KEY
| "CKA_HASH_OF_ISSUER_PUBLIC_KEY" -> Pkcs11.cKA_HASH_OF_ISSUER_PUBLIC_KEY
| "CKA_CHECK_VALUE" -> Pkcs11.cKA_CHECK_VALUE
| "CKA_KEY_TYPE" -> Pkcs11.cKA_KEY_TYPE
| "CKA_SUBJECT" -> Pkcs11.cKA_SUBJECT
| "CKA_ID" -> Pkcs11.cKA_ID
| "CKA_SENSITIVE" -> Pkcs11.cKA_SENSITIVE
| "CKA_ENCRYPT" -> Pkcs11.cKA_ENCRYPT
| "CKA_DECRYPT" -> Pkcs11.cKA_DECRYPT
| "CKA_WRAP" -> Pkcs11.cKA_WRAP
| "CKA_UNWRAP" -> Pkcs11.cKA_UNWRAP
| "CKA_SIGN" -> Pkcs11.cKA_SIGN
| "CKA_SIGN_RECOVER" -> Pkcs11.cKA_SIGN_RECOVER
| "CKA_VERIFY" -> Pkcs11.cKA_VERIFY
| "CKA_VERIFY_RECOVER" -> Pkcs11.cKA_VERIFY_RECOVER
| "CKA_DERIVE" -> Pkcs11.cKA_DERIVE
| "CKA_START_DATE" -> Pkcs11.cKA_START_DATE
| "CKA_END_DATE" -> Pkcs11.cKA_END_DATE
| "CKA_MODULUS" -> Pkcs11.cKA_MODULUS
| "CKA_MODULUS_BITS" -> Pkcs11.cKA_MODULUS_BITS
| "CKA_PUBLIC_EXPONENT" -> Pkcs11.cKA_PUBLIC_EXPONENT
| "CKA_PRIVATE_EXPONENT" -> Pkcs11.cKA_PRIVATE_EXPONENT
| "CKA_PRIME_1" -> Pkcs11.cKA_PRIME_1
| "CKA_PRIME_2" -> Pkcs11.cKA_PRIME_2
| "CKA_EXPONENT_1" -> Pkcs11.cKA_EXPONENT_1
| "CKA_EXPONENT_2" -> Pkcs11.cKA_EXPONENT_2
| "CKA_COEFFICIENT" -> Pkcs11.cKA_COEFFICIENT
| "CKA_PRIME" -> Pkcs11.cKA_PRIME
| "CKA_SUBPRIME" -> Pkcs11.cKA_SUBPRIME
| "CKA_BASE" -> Pkcs11.cKA_BASE
| "CKA_PRIME_BITS" -> Pkcs11.cKA_PRIME_BITS
| "CKA_SUB_PRIME_BITS" -> Pkcs11.cKA_SUB_PRIME_BITS
| "CKA_VALUE_BITS" -> Pkcs11.cKA_VALUE_BITS
| "CKA_VALUE_LEN" -> Pkcs11.cKA_VALUE_LEN
| "CKA_EXTRACTABLE" -> Pkcs11.cKA_EXTRACTABLE
| "CKA_LOCAL" -> Pkcs11.cKA_LOCAL
| "CKA_NEVER_EXTRACTABLE" -> Pkcs11.cKA_NEVER_EXTRACTABLE
| "CKA_ALWAYS_SENSITIVE" -> Pkcs11.cKA_ALWAYS_SENSITIVE
| "CKA_KEY_GEN_MECHANISM" -> Pkcs11.cKA_KEY_GEN_MECHANISM
| "CKA_MODIFIABLE" -> Pkcs11.cKA_MODIFIABLE
| "CKA_ECDSA_PARAMS" -> Pkcs11.cKA_ECDSA_PARAMS
| "CKA_EC_PARAMS" -> Pkcs11.cKA_EC_PARAMS
| "CKA_EC_POINT" -> Pkcs11.cKA_EC_POINT
| "CKA_SECONDARY_AUTH" -> Pkcs11.cKA_SECONDARY_AUTH
| "CKA_AUTH_PIN_FLAGS" -> Pkcs11.cKA_AUTH_PIN_FLAGS
| "CKA_ALWAYS_AUTHENTICATE" -> Pkcs11.cKA_ALWAYS_AUTHENTICATE
| "CKA_WRAP_WITH_TRUSTED" -> Pkcs11.cKA_WRAP_WITH_TRUSTED
| "CKA_HW_FEATURE_TYPE" -> Pkcs11.cKA_HW_FEATURE_TYPE
| "CKA_RESET_ON_INIT" -> Pkcs11.cKA_RESET_ON_INIT
| "CKA_HAS_RESET" -> Pkcs11.cKA_HAS_RESET
| "CKA_PIXEL_X" -> Pkcs11.cKA_PIXEL_X
| "CKA_PIXEL_Y" -> Pkcs11.cKA_PIXEL_Y
| "CKA_RESOLUTION" -> Pkcs11.cKA_RESOLUTION
| "CKA_CHAR_ROWS" -> Pkcs11.cKA_CHAR_ROWS
| "CKA_CHAR_COLUMNS" -> Pkcs11.cKA_CHAR_COLUMNS
| "CKA_COLOR" -> Pkcs11.cKA_COLOR
| "CKA_BITS_PER_PIXEL" -> Pkcs11.cKA_BITS_PER_PIXEL
| "CKA_CHAR_SETS" -> Pkcs11.cKA_CHAR_SETS
| "CKA_ENCODING_METHODS" -> Pkcs11.cKA_ENCODING_METHODS
| "CKA_MIME_TYPES" -> Pkcs11.cKA_MIME_TYPES
| "CKA_MECHANISM_TYPE" -> Pkcs11.cKA_MECHANISM_TYPE
| "CKA_REQUIRED_CMS_ATTRIBUTES" -> Pkcs11.cKA_REQUIRED_CMS_ATTRIBUTES
| "CKA_DEFAULT_CMS_ATTRIBUTES" -> Pkcs11.cKA_DEFAULT_CMS_ATTRIBUTES
| "CKA_SUPPORTED_CMS_ATTRIBUTES" -> Pkcs11.cKA_SUPPORTED_CMS_ATTRIBUTES
| "CKA_WRAP_TEMPLATE" -> Pkcs11.cKA_WRAP_TEMPLATE
| "CKA_UNWRAP_TEMPLATE" -> Pkcs11.cKA_UNWRAP_TEMPLATE
| "CKA_ALLOWED_MECHANISMS" -> Pkcs11.cKA_ALLOWED_MECHANISMS
| "CKA_VENDOR_DEFINED" -> Pkcs11.cKA_VENDOR_DEFINED
  (* Sessions *)
| "CKS_RO_PUBLIC_SESSION" -> Pkcs11.cKS_RO_PUBLIC_SESSION
| "CKS_RO_USER_FUNCTIONS" -> Pkcs11.cKS_RO_USER_FUNCTIONS
| "CKS_RW_PUBLIC_SESSION" -> Pkcs11.cKS_RW_PUBLIC_SESSION
| "CKS_RW_USER_FUNCTIONS" -> Pkcs11.cKS_RW_USER_FUNCTIONS
| "CKS_RW_SO_FUNCTIONS" -> Pkcs11.cKS_RW_SO_FUNCTIONS
  (* Hardware *)
| "CKH_MONOTONIC_COUNTER" -> Pkcs11.cKH_MONOTONIC_COUNTER
| "CKH_CLOCK" -> Pkcs11.cKH_CLOCK
| "CKH_USER_INTERFACE" -> Pkcs11.cKH_USER_INTERFACE
  (* Keys *)
| "CKK_RSA" -> Pkcs11.cKK_RSA
| "CKK_DSA" -> Pkcs11.cKK_DSA
| "CKK_DH" -> Pkcs11.cKK_DH
| "CKK_ECDSA" -> Pkcs11.cKK_ECDSA
| "CKK_EC" -> Pkcs11.cKK_EC
| "CKK_X9_42_DH" -> Pkcs11.cKK_X9_42_DH
| "CKK_KEA" -> Pkcs11.cKK_KEA
| "CKK_GENERIC_SECRET" -> Pkcs11.cKK_GENERIC_SECRET
| "CKK_RC2" -> Pkcs11.cKK_RC2
| "CKK_RC4" -> Pkcs11.cKK_RC4
| "CKK_DES" -> Pkcs11.cKK_DES
| "CKK_DES2" -> Pkcs11.cKK_DES2
| "CKK_DES3" -> Pkcs11.cKK_DES3
| "CKK_CAST" -> Pkcs11.cKK_CAST
| "CKK_CAST3" -> Pkcs11.cKK_CAST3
| "CKK_CAST128" -> Pkcs11.cKK_CAST128
| "CKK_RC5" -> Pkcs11.cKK_RC5
| "CKK_IDEA" -> Pkcs11.cKK_IDEA
| "CKK_SKIPJACK" -> Pkcs11.cKK_SKIPJACK
| "CKK_BATON" -> Pkcs11.cKK_BATON
| "CKK_JUNIPER" -> Pkcs11.cKK_JUNIPER
| "CKK_CDMF" -> Pkcs11.cKK_CDMF
| "CKK_AES" -> Pkcs11.cKK_AES
| "CKK_BLOWFISH" -> Pkcs11.cKK_BLOWFISH
| "CKK_TWOFISH" -> Pkcs11.cKK_TWOFISH
| "CKK_SECURID" -> Pkcs11.cKK_SECURID
| "CKK_HOTP"    -> Pkcs11.cKK_HOTP
| "CKK_ACTI"    -> Pkcs11.cKK_ACTI
| "CKK_CAMELLIA" -> Pkcs11.cKK_CAMELLIA
| "CKK_ARIA"     -> Pkcs11.cKK_ARIA
  (* Certificate *)
| "CKC_X_509" -> Pkcs11.cKC_X_509
| "CKC_X_509_ATTR_CERT" -> Pkcs11.cKC_X_509_ATTR_CERT
| "CKC_WTLS" -> Pkcs11.cKC_WTLS
| "CKC_VENDOR_DEFINED" -> Pkcs11.cKC_VENDOR_DEFINED
| _ -> let s = Printf.sprintf "Unknown PKCS#11 value %s" in_string in failwith(s)

let match_string_to_attribute attribute_string =
  match attribute_string with
   | "CKA_CLASS" -> (Pkcs11.cKA_CLASS, cK_CHAR_PTR)
   | "CKA_TOKEN" -> (Pkcs11.cKA_TOKEN, cK_BOOL)
   | "CKA_PRIVATE" -> (Pkcs11.cKA_PRIVATE, cK_BOOL)
   | "CKA_LABEL" -> (Pkcs11.cKA_LABEL, cK_CHAR_PTR)
   | "CKA_APPLICATION" -> (Pkcs11.cKA_APPLICATION, cK_CHAR_PTR)
   | "CKA_VALUE" -> (Pkcs11.cKA_VALUE, cK_CHAR_PTR)
   | "CKA_OBJECT_ID" -> (Pkcs11.cKA_OBJECT_ID, cK_CHAR_PTR)
   | "CKA_CERTIFICATE_TYPE" -> (Pkcs11.cKA_CERTIFICATE_TYPE, cK_CHAR_PTR)
   | "CKA_ISSUER" -> (Pkcs11.cKA_ISSUER, cK_CHAR_PTR)
   | "CKA_SERIAL_NUMBER" -> (Pkcs11.cKA_SERIAL_NUMBER, cK_CHAR_PTR)
   | "CKA_AC_ISSUER" -> (Pkcs11.cKA_AC_ISSUER, cK_CHAR_PTR)
   | "CKA_OWNER" -> (Pkcs11.cKA_OWNER, cK_CHAR_PTR)
   | "CKA_ATTR_TYPES" -> (Pkcs11.cKA_ATTR_TYPES, cK_CHAR_PTR)
   | "CKA_TRUSTED" -> (Pkcs11.cKA_TRUSTED, cK_BOOL)
   | "CKA_CERTIFICATE_CATEGORY" -> (Pkcs11.cKA_CERTIFICATE_CATEGORY, cK_CHAR_PTR)
   | "CKA_JAVA_MIDP_SECURITY_DOMAIN" -> (Pkcs11.cKA_JAVA_MIDP_SECURITY_DOMAIN, cK_CHAR_PTR)
   | "CKA_URL" -> (Pkcs11.cKA_URL, cK_CHAR_PTR)
   | "CKA_HASH_OF_SUBJECT_PUBLIC_KEY" -> (Pkcs11.cKA_HASH_OF_SUBJECT_PUBLIC_KEY, cK_CHAR_PTR)
   | "CKA_HASH_OF_ISSUER_PUBLIC_KEY" -> (Pkcs11.cKA_HASH_OF_ISSUER_PUBLIC_KEY, cK_CHAR_PTR)
   | "CKA_CHECK_VALUE" -> (Pkcs11.cKA_CHECK_VALUE, cK_CHAR_PTR)
   | "CKA_KEY_TYPE" -> (Pkcs11.cKA_KEY_TYPE, cK_CHAR_PTR)
   | "CKA_SUBJECT" -> (Pkcs11.cKA_SUBJECT, cK_CHAR_PTR)
   | "CKA_ID" -> (Pkcs11.cKA_ID, cK_CHAR_PTR)
   | "CKA_SENSITIVE" -> (Pkcs11.cKA_SENSITIVE, cK_BOOL)
   | "CKA_ENCRYPT" -> (Pkcs11.cKA_ENCRYPT, cK_BOOL)
   | "CKA_DECRYPT" -> (Pkcs11.cKA_DECRYPT, cK_BOOL)
   | "CKA_WRAP" -> (Pkcs11.cKA_WRAP, cK_BOOL)
   | "CKA_UNWRAP" -> (Pkcs11.cKA_UNWRAP, cK_BOOL)
   | "CKA_SIGN" -> (Pkcs11.cKA_SIGN, cK_BOOL)
   | "CKA_SIGN_RECOVER" -> (Pkcs11.cKA_SIGN_RECOVER, cK_BOOL)
   | "CKA_VERIFY" -> (Pkcs11.cKA_VERIFY, cK_BOOL)
   | "CKA_VERIFY_RECOVER" -> (Pkcs11.cKA_VERIFY_RECOVER, cK_BOOL)
   | "CKA_DERIVE" -> (Pkcs11.cKA_DERIVE, cK_BOOL)
   | "CKA_START_DATE" -> (Pkcs11.cKA_START_DATE, cK_CHAR_PTR)
   | "CKA_END_DATE" -> (Pkcs11.cKA_END_DATE, cK_CHAR_PTR)
   | "CKA_MODULUS" -> (Pkcs11.cKA_MODULUS, cK_CHAR_PTR)
   | "CKA_MODULUS_BITS" -> (Pkcs11.cKA_MODULUS_BITS, cK_CHAR_PTR)
   | "CKA_PUBLIC_EXPONENT" -> (Pkcs11.cKA_PUBLIC_EXPONENT, cK_CHAR_PTR)
   | "CKA_PRIVATE_EXPONENT" -> (Pkcs11.cKA_PRIVATE_EXPONENT, cK_CHAR_PTR)
   | "CKA_PRIME_1" -> (Pkcs11.cKA_PRIME_1, cK_CHAR_PTR)
   | "CKA_PRIME_2" -> (Pkcs11.cKA_PRIME_2, cK_CHAR_PTR)
   | "CKA_EXPONENT_1" -> (Pkcs11.cKA_EXPONENT_1, cK_CHAR_PTR)
   | "CKA_EXPONENT_2" -> (Pkcs11.cKA_EXPONENT_2, cK_CHAR_PTR)
   | "CKA_COEFFICIENT" -> (Pkcs11.cKA_COEFFICIENT, cK_CHAR_PTR)
   | "CKA_PRIME" -> (Pkcs11.cKA_PRIME, cK_CHAR_PTR)
   | "CKA_SUBPRIME" -> (Pkcs11.cKA_SUBPRIME, cK_CHAR_PTR)
   | "CKA_BASE" -> (Pkcs11.cKA_BASE, cK_CHAR_PTR)
   | "CKA_PRIME_BITS" -> (Pkcs11.cKA_PRIME_BITS, cK_CHAR_PTR)
   | "CKA_SUB_PRIME_BITS" -> (Pkcs11.cKA_SUB_PRIME_BITS, cK_CHAR_PTR)
   | "CKA_VALUE_BITS" -> (Pkcs11.cKA_VALUE_BITS, cK_CHAR_PTR)
   | "CKA_VALUE_LEN" -> (Pkcs11.cKA_VALUE_LEN, cK_CHAR_PTR)
   | "CKA_EXTRACTABLE" -> (Pkcs11.cKA_EXTRACTABLE, cK_BOOL)
   | "CKA_LOCAL" -> (Pkcs11.cKA_LOCAL, cK_BOOL)
   | "CKA_NEVER_EXTRACTABLE" -> (Pkcs11.cKA_NEVER_EXTRACTABLE, cK_BOOL)
   | "CKA_ALWAYS_SENSITIVE" -> (Pkcs11.cKA_ALWAYS_SENSITIVE, cK_BOOL)
   | "CKA_KEY_GEN_MECHANISM" -> (Pkcs11.cKA_KEY_GEN_MECHANISM, cK_CHAR_PTR)
   | "CKA_MODIFIABLE" -> (Pkcs11.cKA_MODIFIABLE, cK_BOOL)
   | "CKA_ECDSA_PARAMS" -> (Pkcs11.cKA_ECDSA_PARAMS, cK_CHAR_PTR)
   | "CKA_EC_PARAMS" -> (Pkcs11.cKA_EC_PARAMS, cK_CHAR_PTR)
   | "CKA_EC_POINT" -> (Pkcs11.cKA_EC_POINT, cK_CHAR_PTR)
   | "CKA_SECONDARY_AUTH" -> (Pkcs11.cKA_SECONDARY_AUTH, cK_CHAR_PTR)
   | "CKA_AUTH_PIN_FLAGS" -> (Pkcs11.cKA_AUTH_PIN_FLAGS, cK_CHAR_PTR)
   | "CKA_ALWAYS_AUTHENTICATE" -> (Pkcs11.cKA_ALWAYS_AUTHENTICATE, cK_BOOL)
   | "CKA_WRAP_WITH_TRUSTED" -> (Pkcs11.cKA_WRAP_WITH_TRUSTED, cK_BOOL)
   | "CKA_HW_FEATURE_TYPE" -> (Pkcs11.cKA_HW_FEATURE_TYPE, cK_CHAR_PTR)
   | "CKA_RESET_ON_INIT" -> (Pkcs11.cKA_RESET_ON_INIT, cK_BOOL)
   | "CKA_HAS_RESET" -> (Pkcs11.cKA_HAS_RESET, cK_BOOL)
   | "CKA_PIXEL_X" -> (Pkcs11.cKA_PIXEL_X, cK_CHAR_PTR)
   | "CKA_PIXEL_Y" -> (Pkcs11.cKA_PIXEL_Y, cK_CHAR_PTR)
   | "CKA_RESOLUTION" -> (Pkcs11.cKA_RESOLUTION, cK_CHAR_PTR)
   | "CKA_CHAR_ROWS" -> (Pkcs11.cKA_CHAR_ROWS, cK_CHAR_PTR)
   | "CKA_CHAR_COLUMNS" -> (Pkcs11.cKA_CHAR_COLUMNS, cK_CHAR_PTR)
   | "CKA_COLOR" -> (Pkcs11.cKA_COLOR, cK_CHAR_PTR)
   | "CKA_BITS_PER_PIXEL" -> (Pkcs11.cKA_BITS_PER_PIXEL, cK_CHAR_PTR)
   | "CKA_CHAR_SETS" -> (Pkcs11.cKA_CHAR_SETS, cK_CHAR_PTR)
   | "CKA_ENCODING_METHODS" -> (Pkcs11.cKA_ENCODING_METHODS, cK_CHAR_PTR)
   | "CKA_MIME_TYPES" -> (Pkcs11.cKA_MIME_TYPES, cK_CHAR_PTR)
   | "CKA_MECHANISM_TYPE" -> (Pkcs11.cKA_MECHANISM_TYPE, cK_CHAR_PTR)
   | "CKA_REQUIRED_CMS_ATTRIBUTES" -> (Pkcs11.cKA_REQUIRED_CMS_ATTRIBUTES, cK_CHAR_PTR)
   | "CKA_DEFAULT_CMS_ATTRIBUTES" -> (Pkcs11.cKA_DEFAULT_CMS_ATTRIBUTES, cK_CHAR_PTR)
   | "CKA_SUPPORTED_CMS_ATTRIBUTES" -> (Pkcs11.cKA_SUPPORTED_CMS_ATTRIBUTES, cK_CHAR_PTR)
   | "CKA_WRAP_TEMPLATE" -> (Pkcs11.cKA_WRAP_TEMPLATE, cK_CHAR_PTR)
   | "CKA_UNWRAP_TEMPLATE" -> (Pkcs11.cKA_UNWRAP_TEMPLATE, cK_CHAR_PTR)
   | "CKA_ALLOWED_MECHANISMS" -> (Pkcs11.cKA_ALLOWED_MECHANISMS, cK_CHAR_PTR)
   | "CKA_VENDOR_DEFINED" -> (Pkcs11.cKA_VENDOR_DEFINED, cK_CHAR_PTR)
   (* TODO: support any attribute type given its hexadecimal value *)
   | _ -> let s = Printf.sprintf "Unknown attribute %s" attribute_string in failwith(s)


let get_hexadecimal in_string =
  (* If the string has not an even number of characters, left pad it *)
  let in_string = (
    if (String.length in_string) mod 2 <> 0 then
      let new_string = (String.make 1 '0') ^ in_string in
      (new_string) 
    else
      (in_string)
  ) in
  let bin_string = (try Pkcs11.pack in_string with
    _ -> 
      let s = Printf.sprintf "PKCS11AttributeBadFormat %s is not an hexadecimal string" in_string in
      raise(PKCS11AttributeBadFormat(s)) 
  ) in
  (Pkcs11.string_to_char_array bin_string)


let get_value_from_string in_string = 
  (* Try to fetch a known PKCS#11 value *)
  let char_value = (try Pkcs11.int_to_ulong_char_array (match_string_to_p11_value in_string) with
    _ -> 
      (* We could not fetch a PKCS#11 value, get the hexadecimal string *)
      (try get_hexadecimal in_string with
          _ -> 
            let s = Printf.sprintf "PKCS11AttributeBadFormat %s is neither a PKCS#11 value nor a hexadecimal string" in_string in
            raise(PKCS11AttributeBadFormat(s)) 
      )
   ) in
   (char_value)


let get_attribute_value_from_string in_string the_type =
  if compare the_type cK_CHAR_PTR = 0 then
    if String.length in_string >= 2 then
      (* Do we have an ASCII string? *)
      if (in_string.[0] = '"') && (in_string.[(String.length in_string) - 1] = '"') then
        (Pkcs11.string_to_char_array (String.sub in_string 1 ((String.length in_string) - 2)))
      else
        (* Parse the hexadecimal chain or get the associated PKCS#11 value *)
        (get_value_from_string in_string)
    else
      (* Parse the hexadecimal chain or get the associated PKCS#11 value *)
      (get_value_from_string in_string)
  else if compare the_type cK_BOOL = 0 then
    (* Parse a boolean value *)
    if (compare in_string "TRUE" = 0) || (compare in_string "1" = 0) then
      (Pkcs11.bool_to_char_array Pkcs11.cK_TRUE)
    else if (compare in_string "FALSE" = 0) || (compare in_string "0" = 0) then
      (Pkcs11.bool_to_char_array Pkcs11.cK_FALSE)
    else
      (* Not a boolean representation *)
        let s = Printf.sprintf "PKCS11AttributeBadFormat %s is not a boolean representation (TRUE or FALSE or 1 or 0)" in_string in
        raise(PKCS11AttributeBadFormat(s))
  else
    let s = Printf.sprintf "PKCS11AttributeBadFormat unknown error when parsing %s" in_string in
    raise(PKCS11AttributeBadFormat(s))
 
      
let get_attribute_from_string in_string =
  (* FIXME: treat the case when whe have a comma or = in a provided ASCII string *)
  (* First, we remove all the spaces when necessary  *)
  let in_string = Str.global_replace (Str.regexp " ") "" in_string in
  (* Second, we split the string with = *)
  let splitted_string = Str.split (Str.regexp "=") in_string in
  if (List.length splitted_string) = 2 then
    (* Get the concerned attribute *)
    let attrib_string = List.nth splitted_string 0 in
    let attrib_value = List.nth splitted_string 1 in
    let (the_attribute, the_attribute_type) = match_string_to_attribute attrib_string in
    (* Get the attribute value *)
    let the_attribute_value = get_attribute_value_from_string attrib_value the_attribute_type in
    (* Return the couple attribute * the_binary_value *)
    (the_attribute, the_attribute_value)
  else
    let s = Printf.sprintf "Bad PKCS#11 attributes formatting in %s" in_string in
    raise(PKCS11AttributeBadFormat(s))

let get_attributes_to_set in_string =
  (* Get the attributes to set from input string *)
  (* and return a template array                 *)
  (* First, we split the string with the ','     *)
  let splitted_string_list = Str.split (Str.regexp ",") in_string in
  (* Get each substring *)
  let interpreted_attributes_list = List.map (
    fun attribute_string ->
     (* For each substring, get its type and value *)
     let (the_attribute, the_attribute_value) = get_attribute_from_string attribute_string in
     ({Pkcs11.type_ = the_attribute; Pkcs11.value = the_attribute_value})
  ) splitted_string_list in
  (Array.of_list interpreted_attributes_list)

let get_dump_attribute_from_string in_string =
  (* FIXME: treat the case when whe have a comma or = in a provided ASCII string *)
  (* First, we remove all the spaces when necessary  *)
  let in_string = Str.global_replace (Str.regexp " ") "" in_string in
  (* Then, we get the attribute *)
  (match_string_to_attribute in_string)


let get_attributes_to_dump in_string =
  (* Get the attributes to set from input string *)
  (* and return a template array                 *)
  (* First, we split the string with the ','     *)
  let splitted_string_list = Str.split (Str.regexp ",") in_string in
  (* Get each substring *)
  let interpreted_attributes_list = List.map (
    fun attribute_string ->
     (* For each substring, get its type and value *)
     let (the_attribute, the_attribute_type) = get_dump_attribute_from_string attribute_string in
     (the_attribute, the_attribute_type)
  ) splitted_string_list in
  (Array.of_list interpreted_attributes_list)
 
