open Printf
open P11_common
open P11_objects

let generate_rsa_template keysize pub_template =
    let public_exponent = Pkcs11.string_to_char_array (Pkcs11.pack "010001") in
    let pub_template = templ_append pub_template Pkcs11.cKA_PUBLIC_EXPONENT public_exponent in

    let modulus_bits = match keysize with
        512n -> Pkcs11.int_to_ulong_char_array keysize
        |1024n -> Pkcs11.int_to_ulong_char_array keysize
        |2048n -> Pkcs11.int_to_ulong_char_array keysize
        |4096n -> Pkcs11.int_to_ulong_char_array keysize
        |8192n -> Pkcs11.int_to_ulong_char_array keysize
        |16384n -> Pkcs11.int_to_ulong_char_array keysize
        | _ -> raise UnsupportedRSAKeySize in
    let pub_template = templ_append pub_template Pkcs11.cKA_MODULUS_BITS modulus_bits in
           
    (pub_template)

let generate_dsa_template session obj_domain_param pub_template =
    let obj_template = [||] in
    let obj_template = templ_append obj_template Pkcs11.cKA_PRIME [||] in
    let obj_template = templ_append obj_template Pkcs11.cKA_SUBPRIME [||] in
    let obj_template = templ_append obj_template Pkcs11.cKA_BASE [||] in
    let (ret_value, obj_template) = get_attributes ~continue_on_failure:false session obj_domain_param obj_template in
    (merge_templates pub_template obj_template)

let generate_dsa_domain_parameters session label keysize =
    let obj_template = [||] in
    let prime_bits = match keysize with
        512n -> Pkcs11.int_to_ulong_char_array keysize
        |1024n -> Pkcs11.int_to_ulong_char_array keysize
        | _ -> raise UnsupportedDSAKeySize in
    let obj_template = templ_append obj_template Pkcs11.cKA_PRIME_BITS prime_bits in
    let obj_template = templ_append obj_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let obj_template = append_some_value_to_template Pkcs11.cKA_LABEL label obj_template in

    let mech = { Pkcs11.mechanism = Pkcs11.cKM_DSA_PARAMETER_GEN ; Pkcs11.parameter = [||] } in

    (* GenerateKey *)
    let (ret_value, params_) = Pkcs11.c_GenerateKey session mech obj_template in
    let _ = check_ret ret_value C_GenerateKeyError false in
    printf "C_GenerateKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    (params_, ret_value)

let generate_ecc_template named_curve pub_template use_named =
    if use_named then
        let ec_params = Pkcs11.string_to_char_array (Pkcs11.pack (Ecc_helper.match_named_curve_to_oid named_curve)) in
        let pub_template = templ_append pub_template Pkcs11.cKA_EC_PARAMS ec_params in
        (pub_template)
    else
        let ec_params = Pkcs11.string_to_char_array (Pkcs11.pack (Ecc_helper.match_named_curve_to_explicit_params named_curve)) in
        let pub_template = templ_append pub_template Pkcs11.cKA_EC_PARAMS ec_params in
        (pub_template)


let generate_key_pair_template keyslabel keysid =
    let pub_template = [||] in
    let priv_template = [||] in

    let pubclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY in
    let pub_template = templ_append pub_template Pkcs11.cKA_CLASS pubclass in

    let privclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY in
    let priv_template = templ_append priv_template Pkcs11.cKA_CLASS privclass in

    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_LABEL keyslabel pub_template priv_template in
    let (pub_template, priv_template) = append_rsa_template Pkcs11.cKA_ID keysid pub_template priv_template in

    let pub_template = templ_append pub_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_MODIFIABLE Pkcs11.false_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_ENCRYPT Pkcs11.false_ in
    let pub_template = templ_append pub_template Pkcs11.cKA_VERIFY Pkcs11.true_ in
    (*
    let pub_template = templ_append pub_template Pkcs11.cKA_VERIFY_RECOVER Pkcs11.false_ in
    *)
    let pub_template = templ_append pub_template Pkcs11.cKA_WRAP Pkcs11.false_ in

    let priv_template = templ_append priv_template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_MODIFIABLE Pkcs11.false_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_DECRYPT Pkcs11.false_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_SIGN Pkcs11.true_ in
    (*
    let priv_template = templ_append priv_template Pkcs11.cKA_SIGN_RECOVER Pkcs11.false_ in
    *)
    let priv_template = templ_append priv_template Pkcs11.cKA_UNWRAP Pkcs11.false_ in
    let priv_template = templ_append priv_template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    (*
    let priv_template = templ_append priv_template Pkcs11.cKA_EXTRACTABLE Pkcs11.false_ in
    *)
    let priv_template = templ_append priv_template Pkcs11.cKA_SENSITIVE Pkcs11.true_ in
    (pub_template, priv_template)

let generate_ecc_key_pair_template named_curve keylabel keysid use_named =
    let (pub_template, priv_template) = generate_key_pair_template keylabel keysid in
    ((generate_ecc_template named_curve pub_template use_named), priv_template)

let generate_rsa_key_pair_template keypairsize keylabel keysid =
    let (pub_template, priv_template) = generate_key_pair_template keylabel keysid in
    ((generate_rsa_template keypairsize pub_template), priv_template)

let generate_dsa_key_pair_template session obj_domain_param keylabel keysid =
    let (pub_template, priv_template) = generate_key_pair_template keylabel keysid in
    ((generate_dsa_template session obj_domain_param pub_template), priv_template)


(* Perform the C_GenerateKeyPair *)
let generate_key_pair session pub_template priv_template mech continue_on_error =
    (* GenerateKeyPair *)
    let (ret_value, pubkey_, privkey_) = Pkcs11.c_GenerateKeyPair session mech pub_template priv_template in
    let _ = check_ret ret_value C_GenerateKeyPairError continue_on_error in
    printf "C_GenerateKeyPair ret: %s\n" (Pkcs11.match_cKR_value ret_value);
    (pubkey_, privkey_, ret_value)

let generate_ecc_key_pair session pub_template priv_template parameters continue_on_error =
    let mech = { Pkcs11.mechanism = Pkcs11.cKM_EC_KEY_PAIR_GEN ; Pkcs11.parameter = parameters } in
    (generate_key_pair session pub_template priv_template mech continue_on_error)

let generate_rsa_key_pair session pub_template priv_template parameters =
    let mech = { Pkcs11.mechanism = Pkcs11.cKM_RSA_PKCS_KEY_PAIR_GEN ; Pkcs11.parameter = parameters } in
    (generate_key_pair session pub_template priv_template mech false)

let generate_dsa_key_pair session pub_template priv_template parameters =
    let mech = { Pkcs11.mechanism = Pkcs11.cKM_DSA_KEY_PAIR_GEN ; Pkcs11.parameter = parameters } in
    (generate_key_pair session pub_template priv_template mech false)

(* Generic function to generate a template for symmetric keys *)
let generate_symkey_template mechanism keysize keylabel keyid provided_template_array =
    let template = [||] in

    let keyclass = Pkcs11.int_to_ulong_char_array Pkcs11.cKO_SECRET_KEY in
    let template = templ_append template Pkcs11.cKA_CLASS keyclass in
 
    let key_type = match mechanism with
        | ("aes" | "AES")   -> if compare keysize 128n <> 0 then raise UnsupportedSymmetricKeySize else Pkcs11.cKK_AES
        | ("des" | "DES")   -> if compare keysize 64n  <> 0 then raise UnsupportedSymmetricKeySize else Pkcs11.cKK_DES
        | ("des2" | "DES2") -> if compare keysize 128n <> 0 then raise UnsupportedSymmetricKeySize else Pkcs11.cKK_DES2
        | ("des3" | "DES3") -> if compare keysize 192n <> 0 then raise UnsupportedSymmetricKeySize else Pkcs11.cKK_DES3
        | ("generic") -> Pkcs11.cKK_GENERIC_SECRET
        | _ -> raise UnsupportedSymmetricKeySize in

    let template =  match mechanism with
        | ("aes" | "AES")   -> templ_append template Pkcs11.cKA_VALUE_LEN (Pkcs11.int_to_ulong_char_array (Nativeint.div keysize 8n))
        | ("generic") -> templ_append template Pkcs11.cKA_VALUE_LEN (Pkcs11.int_to_ulong_char_array (Nativeint.div keysize 8n))
        | _ -> template in 

    let template = (
      match keylabel with
        | Some x -> templ_append template Pkcs11.cKA_LABEL (Pkcs11.string_to_char_array x)
        | None -> template
    ) in
    let template = (
      match keyid with
        | Some x -> templ_append template Pkcs11.cKA_ID (Pkcs11.string_to_char_array x)
        | None -> template
    ) in  
    let template = templ_append template Pkcs11.cKA_KEY_TYPE (Pkcs11.int_to_ulong_char_array key_type) in 
    let template = templ_append template Pkcs11.cKA_TOKEN Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_PRIVATE Pkcs11.true_ in
    let template = templ_append template Pkcs11.cKA_EXTRACTABLE Pkcs11.false_ in
    let template = templ_append template Pkcs11.cKA_SENSITIVE Pkcs11.true_ in
    let template = merge_templates template provided_template_array in
    (template)

(* Generic function to generate a symmetric key *)
let generate_symkey mechstring keysize keylabel keyid mechparams provided_template_array session_ =
  let mechanism = match mechstring with
        | ("aes" | "AES")   -> Pkcs11.cKM_AES_KEY_GEN
        | ("des" | "DES")   -> Pkcs11.cKM_DES_KEY_GEN
        | ("des2" | "DES2") -> Pkcs11.cKM_DES2_KEY_GEN
        | ("des3" | "DES3") -> Pkcs11.cKM_DES3_KEY_GEN
        | "generic" -> Pkcs11.cKM_GENERIC_SECRET_KEY_GEN
        | _ -> raise UnsupportedSymmetricKeyMechanism in
  let template = generate_symkey_template mechstring keysize keylabel keyid provided_template_array in
  let (ret_value, _) = Pkcs11.c_GenerateKey session_ {Pkcs11.mechanism = mechanism; Pkcs11.parameter = mechparams} template in
  let _ = check_ret ret_value C_GenerateKeyError false in
  printf "C_GenerateKey ret: %s\n" (Pkcs11.match_cKR_value ret_value)
