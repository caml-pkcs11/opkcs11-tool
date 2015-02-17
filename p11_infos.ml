open P11_common
open P11_objects
open Printf

(* Replace cK(A|F|R|...)_ by CK-_ from the helpers to deal with Caml case *)
let caml_case_replace in_string =
  let regexp = Str.regexp "cK\\(A\\|F\\|R\\|K\\|M\\|O\\|C\\)_" in
  (Str.replace_first regexp "CK\\1_" in_string)

let match_cKF_token_value a = match a with
| 1n -> "cKF_RNG"
| 2n -> "cKF_WRITE_PROTECTED"
| 4n -> "cKF_LOGIN_REQUIRED"
| 8n -> "cKF_USER_PIN_INITIALIZED"
| 32n -> "cKF_RESTORE_KEY_NOT_NEEDED"
| 64n -> "cKF_CLOCK_ON_TOKEN"
| 256n -> "cKF_PROTECTED_AUTHENTICATION_PATH"
| 512n -> "cKF_DUAL_CRYPTO_OPERATIONS"
| 1024n -> "cKF_TOKEN_INITIALIZED"
| 2048n -> "cKF_SECONDARY_AUTHENTICATION"
| 65536n -> "cKF_USER_PIN_COUNT_LOW"
| 131072n -> "cKF_USER_PIN_FINAL_TRY"
| 262144n -> "cKF_USER_PIN_LOCKED"
| 524288n -> "cKF_USER_PIN_TO_BE_CHANGED"
| 1048576n -> "cKF_SO_PIN_COUNT_LOW"
| 2097152n -> "cKF_SO_PIN_FINAL_TRY"
| 4194304n -> "cKF_SO_PIN_LOCKED"
| 8388608n -> "cKF_SO_PIN_TO_BE_CHANGED"
| _ -> "cKF_UNKNOWN!"

let check_bit_on flag bit =
    (Nativeint.logand flag bit = bit)

(* FIXME: Handle unkown flags *)
let print_token_features flag feature =
    if (check_bit_on flag feature) then
      Printf.printf ", %s" (caml_case_replace (match_cKF_token_value feature));
    ()

let parse_cKF_flags flags =
    let supported_features = [| Pkcs11.cKF_RNG; Pkcs11.cKF_WRITE_PROTECTED;
				Pkcs11.cKF_LOGIN_REQUIRED; Pkcs11.cKF_USER_PIN_INITIALIZED;
				Pkcs11.cKF_RESTORE_KEY_NOT_NEEDED; Pkcs11.cKF_CLOCK_ON_TOKEN;
				Pkcs11.cKF_PROTECTED_AUTHENTICATION_PATH; Pkcs11.cKF_DUAL_CRYPTO_OPERATIONS;
				Pkcs11.cKF_TOKEN_INITIALIZED; Pkcs11.cKF_SECONDARY_AUTHENTICATION;
				Pkcs11.cKF_USER_PIN_COUNT_LOW; Pkcs11.cKF_USER_PIN_FINAL_TRY;
				Pkcs11.cKF_USER_PIN_LOCKED; Pkcs11.cKF_USER_PIN_TO_BE_CHANGED;
				Pkcs11.cKF_SO_PIN_COUNT_LOW; Pkcs11.cKF_SO_PIN_FINAL_TRY;
				Pkcs11.cKF_SO_PIN_LOCKED; Pkcs11.cKF_SO_PIN_TO_BE_CHANGED; |] in

    let _ = Array.iter (print_token_features flags) supported_features in
    ()

let print_token_info = fun token_info_ ->
        if (check_bit_on token_info_.Pkcs11.ck_token_info_flags Pkcs11.cKF_TOKEN_INITIALIZED) then
        begin
          Printf.printf "  token label: %s\n" (Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_label);
          Printf.printf "  token manuf: %s\n" (Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_manufacturer_id);
          Printf.printf "  token model: %s\n" (Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_model);
          Printf.printf "  token flags:";
          parse_cKF_flags token_info_.Pkcs11.ck_token_info_flags;
          Printf.printf "\n";
        end
        else
        begin
          Printf.printf " token is NOT INITIALIZED\n";
        end;
	()

(*********** TOKEN AND SLOT *********************************)
let print_info = fun info_ ->
    (* Token info *)
    let info_cc_major = Printf.sprintf "%d" (Char.code info_.Pkcs11.ck_info_cryptoki_version.Pkcs11.major) in
    let info_cc_minor = Printf.sprintf "%d" (Char.code info_.Pkcs11.ck_info_cryptoki_version.Pkcs11.minor) in
    let manufacturer_id = Pkcs11.char_array_to_string info_.Pkcs11.ck_info_manufacturer_id in
    let library = Pkcs11.char_array_to_string info_.Pkcs11.ck_info_library_description in
    let library_major = Printf.sprintf "%d" (Char.code info_.Pkcs11.ck_info_library_version.Pkcs11.major) in
    let library_minor = Printf.sprintf "%d" (Char.code info_.Pkcs11.ck_info_library_version.Pkcs11.minor) in
    printf "Cryptoki version : %s.%s\n" info_cc_major info_cc_minor;
    printf "Manufacturer     : %s\n" manufacturer_id;
    printf "Library          : %s (ver %s.%s)\n" library library_major library_minor

let print_slots = fun slot ->
	(* GetSlotInfo *)
    let (ret_value, slot_info_) = Pkcs11.mL_CK_C_GetSlotInfo slot in
    let _ = check_ret ret_value C_GetSlotInfoError false in
    dbg_print !do_verbose "C_GetSlotInfo" ret_value;
    (* Slot description *)
    let slot_desc = Pkcs11.char_array_to_string slot_info_.Pkcs11.ck_slot_info_slot_description in
    printf "Slot %s description: %s\n" (Nativeint.to_string slot) slot_desc;

    if (check_bit_on slot_info_.Pkcs11.ck_slot_info_flags Pkcs11.cKF_TOKEN_PRESENT) then
        (* GetTokenInfo *)
        let (ret_value, token_info_) = Pkcs11.mL_CK_C_GetTokenInfo slot in
        let _ = check_ret ret_value C_GetTokenInfoError false in
        dbg_print !do_verbose "C_GetTokenInfo" ret_value;
        if (check_bit_on token_info_.Pkcs11.ck_token_info_flags Pkcs11.cKF_TOKEN_INITIALIZED) then
          begin
            (* Token info *)
            let token_label = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_label in
            let token_manufacturer_id = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_manufacturer_id in
            let token_model = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_model in
            let token_serial_number = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_serial_number in
            let token_utc_time = Pkcs11.char_array_to_string token_info_.Pkcs11.ck_token_info_utc_time in
            let token_max_session_count = token_info_.Pkcs11.ck_token_info_max_session_count in
            printf "  Token label:  %s\n" token_label;
            printf "  Token id:     %s\n" token_manufacturer_id;
            printf "  Token model:  %s\n" token_model;
            printf "  Token serial: %s\n" token_serial_number;
            printf "  Token UTC:    %s\n" token_utc_time;
            printf "  Token max_session:  %s\n" (Nativeint.to_string token_max_session_count)
          end
		else
	      (* Token in not initialized *)
            printf "  (not initialized)\n";
    else
	  (* No token in slot *)
        printf "  (empty)\n";
	()

(*********** ATTRIBUTES *********************************)
(* Print an attribute depending on its class       *)
let print_cka_attr attr attr_class ret_value pretty_printer =
  let attr_string = (
    match pretty_printer with
    | None -> caml_case_replace (Pkcs11.match_cKA_value (attr.Pkcs11.type_))
    | Some x -> x
  ) in
  if check_ret_ok ret_value then
    let to_print = 
    (if compare attr_class cK_BOOL = 0 then
      Pkcs11.sprint_bool_attribute_value (Pkcs11.char_array_to_bool attr.Pkcs11.value)
    else if  compare attr_class cK_STRING = 0 then
      "\"" ^ Pkcs11.char_array_to_string attr.Pkcs11.value ^ "\""
    else if  compare attr_class cK_CHAR_PTR = 0 then
      let s = (Pkcs11.sprint_hex_array attr.Pkcs11.value) in
      if String.length s = 2 then
        ""
      else
        "0x" ^ (Str.global_replace (Str.regexp "'") "" s)
    else if  compare attr_class cK_INTEGER = 0 then
      Printf.sprintf "%nd" (Pkcs11.char_array_to_ulong attr.Pkcs11.value)
    else if  compare attr_class cK_CKC = 0 then
      caml_case_replace (Pkcs11.match_cKC_value (Pkcs11.char_array_to_ulong attr.Pkcs11.value))
    else if  compare attr_class cK_CKM = 0 then
      caml_case_replace (Pkcs11.match_cKM_value (Pkcs11.char_array_to_ulong attr.Pkcs11.value))
    else if  compare attr_class cK_CKF = 0 then
      caml_case_replace (Pkcs11.match_cKF_value (Pkcs11.char_array_to_ulong attr.Pkcs11.value))
    else if  compare attr_class cK_CKO = 0 then
      caml_case_replace (Pkcs11.match_cKO_value (Pkcs11.char_array_to_ulong attr.Pkcs11.value))
    else if  compare attr_class cK_CKK = 0 then
      caml_case_replace (Pkcs11.match_cKK_value (Pkcs11.char_array_to_ulong attr.Pkcs11.value))
    else
      failwith "Error: unknown attribute type to print") in
    Printf.printf " %-32s: %s\n" attr_string to_print
  else
    Printf.printf " %-32s: %s\n" attr_string "Unsupported by token";
    () 

let print_attr session_ object_ attr_type attr_class pretty_printer =
    let templ = [||] in
    let templ = templ_append templ attr_type [||] in
    let (ret, templ) = get_attributes ~continue_on_failure:true session_ object_ templ in
    print_cka_attr templ.(0) attr_class ret.(0) pretty_printer;
    ()

let do_print_attributes the_attributes session_ object_ =
    Array.iter (
      fun (attr, attr_class, do_print, pretty_printer) -> 
        if do_print = true then
          print_attr session_ object_ attr attr_class pretty_printer
        else
          ()
    ) the_attributes;
    ()

let print_myclass_short in_string =
  Printf.printf " ---------------------------------\n";
  Printf.printf "| Object type: %s \n" in_string;
  Printf.printf " ---------------------------------\n";
  ()

(*** Common attributes ***)
let common_attrs = [|
                      (Pkcs11.cKA_CLASS, cK_CKO, true, None);
                      (Pkcs11.cKA_PRIVATE, cK_BOOL, true, None);
                      (Pkcs11.cKA_LABEL, cK_STRING, true, Some "Label");
                      (Pkcs11.cKA_MODIFIABLE, cK_BOOL, true, None) 
                    |]

let print_common_objects_attrs session_ object_ =
    Printf.printf " %-32s\n" "------ COMMON attributes ------" ;
    do_print_attributes common_attrs session_ object_;
    ()

(*** Common keys attributes ****)
let common_key_attrs = [| (Pkcs11.cKA_LOCAL, cK_BOOL, true, None);
                          (Pkcs11.cKA_ID, cK_CHAR_PTR, true, Some "ID");
                          (Pkcs11.cKA_KEY_TYPE, cK_CKK, true, None);
                          (Pkcs11.cKA_PRIVATE, cK_BOOL, true, None);
                        |] 

let print_common_keys_attrs session_ object_ =
    print_common_objects_attrs session_ object_;
    Printf.printf " %-32s\n" "------ COMMON KEY attributes ------" ;
    do_print_attributes common_key_attrs session_ object_;
    ()

(*** Secret keys attributes ****)
let secret_attrs =    [| 
                         (Pkcs11.cKA_ENCRYPT, cK_BOOL, true, None); 
                         (Pkcs11.cKA_DECRYPT, cK_BOOL, true, None);
                         (Pkcs11.cKA_SIGN, cK_BOOL, true, None);
                         (Pkcs11.cKA_VERIFY, cK_BOOL, true, None);
                         (Pkcs11.cKA_WRAP, cK_BOOL, true, None);
                         (Pkcs11.cKA_UNWRAP, cK_BOOL, true, None);
                         (Pkcs11.cKA_EXTRACTABLE, cK_BOOL, true, None);
                         (Pkcs11.cKA_SENSITIVE, cK_BOOL, true, None); 
                         (Pkcs11.cKA_ALWAYS_SENSITIVE, cK_BOOL, true, None);
                         (Pkcs11.cKA_EXTRACTABLE, cK_BOOL, true, None); 
                         (Pkcs11.cKA_NEVER_EXTRACTABLE, cK_BOOL, true, None);
                         (Pkcs11.cKA_WRAP_WITH_TRUSTED, cK_BOOL, true, None); 
                         (Pkcs11.cKA_VALUE_LEN, cK_INTEGER, true, None);
                         (Pkcs11.cKA_CHECK_VALUE, cK_CHAR_PTR, true, Some "Checksum")
                       |]                 

let print_secret_key_attrs session_ object_ =
    print_common_keys_attrs session_ object_;
    Printf.printf " %-32s\n" "------ SECRET-KEYS attributes ------" ;
    do_print_attributes secret_attrs session_ object_;
    ()    

(*** Public keys attributes ****)
let pub_attrs = [| (Pkcs11.cKA_ENCRYPT, cK_BOOL, true, None);
                   (Pkcs11.cKA_WRAP, cK_BOOL, true, None);
                   (Pkcs11.cKA_VERIFY, cK_BOOL, true, None);
                   (Pkcs11.cKA_VERIFY_RECOVER, cK_BOOL, true, None);
                   (Pkcs11.cKA_TRUSTED, cK_BOOL, true, None);
                |]
                      
(*** RSA Public keys attributes ****)
let rsa_pub_attrs =    [| (Pkcs11.cKA_MODULUS, cK_CHAR_PTR, true, None);
                          (Pkcs11.cKA_MODULUS_BITS, cK_INTEGER, true, None);
                          (Pkcs11.cKA_PUBLIC_EXPONENT, cK_CHAR_PTR, true, None)
                       |]

(*** DSA Public keys attributes ****)
let dsa_pub_attrs = [| (Pkcs11.cKA_PRIME, cK_CHAR_PTR, true, Some "CKA_PRIME");
                       (Pkcs11.cKA_SUBPRIME, cK_CHAR_PTR, true, Some "CKA_SUBPRIME");
                       (Pkcs11.cKA_BASE, cK_CHAR_PTR, true, Some "CKA_BASE");
                       (Pkcs11.cKA_VALUE, cK_CHAR_PTR, true, Some "CKA_VALUE")
                    |]

(*** DH Public keys attributes ****)
let dh_pub_attrs = [| (Pkcs11.cKA_PRIME, cK_CHAR_PTR, true, Some "CKA_PRIME");
                      (Pkcs11.cKA_BASE, cK_CHAR_PTR, true, Some "CKA_BASE");
                      (Pkcs11.cKA_VALUE, cK_CHAR_PTR, true, Some "CKA_VALUE")
                   |]


(*** EC Public keys attributes ****)
let ec_pub_attrs = [| (Pkcs11.cKA_EC_PARAMS, cK_CHAR_PTR, true, Some "CKA_EC_PARAMS");
                      (Pkcs11.cKA_EC_POINT, cK_CHAR_PTR, true, Some "CKA_EC_POINT")
                   |]

let print_public_key_attrs session_ object_ =
    print_common_keys_attrs session_ object_;
    Printf.printf " %-32s\n" "------ PUBLIC-KEY attributes ------" ;
    do_print_attributes pub_attrs session_ object_;
    let keytype_templ = [||] in
    let keytype_templ = templ_append keytype_templ Pkcs11.cKA_KEY_TYPE [||] in
    let (_, keytype_templ) = get_attributes session_ object_ keytype_templ in
    let mykeytype = (Pkcs11.char_array_to_ulong keytype_templ.(0).Pkcs11.value) in
    let mykeytype = Pkcs11.match_cKK_value mykeytype in
    let msg = (match mykeytype with
      | "cKK_RSA" -> print_myclass_short "RSA public key"; do_print_attributes rsa_pub_attrs session_ object_; ""
      | "cKK_DSA" -> print_myclass_short "DSA public key"; do_print_attributes dsa_pub_attrs session_ object_; ""
      | "cKK_EC" -> print_myclass_short "EC public key"; do_print_attributes ec_pub_attrs session_ object_; ""
      | "cKK_DH" -> print_myclass_short "DH public key"; do_print_attributes dh_pub_attrs session_ object_; ""
      | "cKK_X9_42_DH" -> print_myclass_short "X9.42 DH public key"; do_print_attributes dsa_pub_attrs session_ object_; ""
      | "cKK_KEA" -> print_myclass_short "KEA public key"; do_print_attributes dsa_pub_attrs session_ object_; ""
      | _ -> failwith "Sorry unknown public key type" ) in
    Printf.printf "%s" msg;
    ()

(*** Private keys attributes ****)
let priv_attrs = [| (Pkcs11.cKA_DECRYPT, cK_BOOL, true, None); 
                    (Pkcs11.cKA_UNWRAP, cK_BOOL, true, None);
                    (Pkcs11.cKA_SIGN, cK_BOOL, true, None); 
                    (Pkcs11.cKA_SIGN_RECOVER, cK_BOOL, true, None);
                    (Pkcs11.cKA_SENSITIVE, cK_BOOL, true, None); 
                    (Pkcs11.cKA_ALWAYS_SENSITIVE, cK_BOOL, true, None);
                    (Pkcs11.cKA_EXTRACTABLE, cK_BOOL, true, None); 
                    (Pkcs11.cKA_NEVER_EXTRACTABLE, cK_BOOL, true, None);
                    (Pkcs11.cKA_WRAP_WITH_TRUSTED, cK_BOOL, true, None); 
                    (Pkcs11.cKA_ALWAYS_AUTHENTICATE, cK_BOOL, true, None)
                 |]

let print_private_key_attrs session_ object_ =
    print_common_keys_attrs session_ object_;
    Printf.printf " %-32s\n" "------ PRIVATE-KEY attributes ------" ;
    do_print_attributes priv_attrs session_ object_;
    ()

(*** Certificate attributes ****)
let cert_attrs =  [| (Pkcs11.cKA_LABEL, cK_STRING, true, Some "Label");
                     (Pkcs11.cKA_ID, cK_CHAR_PTR, true, Some "ID");
                     (Pkcs11.cKA_CERTIFICATE_TYPE, cK_CKC, true, None)
                   |] 


let print_certificate_attrs session_ object_ =
    print_common_objects_attrs session_ object_;
    Printf.printf " %-32s\n" "------ CERTIFICATE attributes ------" ;
    do_print_attributes cert_attrs session_ object_;
    ()

(*** DSA Domain parameters attributes ****)
let dsa_domain_parameters_attrs = [| (Pkcs11.cKA_PRIME, cK_CHAR_PTR, true, Some "CKA_PRIME");
                    (Pkcs11.cKA_SUBPRIME, cK_CHAR_PTR, true, Some "CKA_SUBPRIME");
                    (Pkcs11.cKA_BASE, cK_CHAR_PTR, true, Some "CKA_BASE");
                    (Pkcs11.cKA_PRIME_BITS, cK_INTEGER, true, None)
                 |]

let print_dsa_domain_parameters_attrs session_ object_ =
    print_common_objects_attrs session_ object_;
    Printf.printf " %-32s\n" "------ DSA-DOMAIN-PARAMETERS attributes ------" ;
    do_print_attributes dsa_domain_parameters_attrs session_ object_;
    ()

(******************************)
let check_pkcs11_bool the_array = 
  let out = ref false in
  Array.iter (
    fun elem -> 
      if compare elem (Char.chr 0) = 0 then
        out := !out || false
      else
        out := !out || true
  ) the_array;
  (!out)

let print_additional_attributes session_ object_ =
  if compare !dump_attributes_string "" <> 0 then
    let the_array = get_attributes_to_dump !dump_attributes_string in
    Printf.printf " %-32s\n" "------ ADDITIONAL ASKED attributes ------" ;
    Printf.printf " %-32s\n" "|     hexadecimal big endian format     |" ;
    Printf.printf " %-32s\n" "-----------------------------------------" ;
    Array.iter (
      fun (attrib_type, attrib_class) ->
        let (ret, temp) = (try get_attributes session_ object_ [| {Pkcs11.type_ = attrib_type; Pkcs11.value = [||]} |] with 
          _ -> ([|Pkcs11.cKR_GENERAL_ERROR|], [||])) in
        if (compare ret.(0) Pkcs11.cKR_OK <> 0) || (compare temp [||] = 0) then
          (* The attribute could not be retrieved *)            
          Printf.printf " %-32s: Attribute unsupported/Can't be retrieved\n" (caml_case_replace (Pkcs11.match_cKA_value attrib_type))
        else
          (* The attribute could be retrieved *)
          let s = (
            if compare attrib_class cK_BOOL = 0 then
              (* We have a boolean attribute *)
              if check_pkcs11_bool temp.(0).Pkcs11.value = false then
                ("FALSE")
              else
                ("TRUE")
            else
             (* We have an hexadecimal array *)
             let s = Pkcs11.sprint_hex_array temp.(0).Pkcs11.value in
             ("0x" ^ (Str.global_replace (Str.regexp "'") "" s))
          ) in
          Printf.printf " %-32s: %s\n" (caml_case_replace (Pkcs11.match_cKA_value temp.(0).Pkcs11.type_)) s
    ) the_array;
    Printf.printf "\n";
  else
    Printf.printf "\n";
    (* Do nothing if we are not asked to dump additional attributes *)
    ()


let print_object_attributes session_ object_ =
    let class_templ = [||] in
    let class_templ = templ_append class_templ Pkcs11.cKA_CLASS [||] in
    let (_, class_templ) = get_attributes session_ object_ class_templ in
    let myclass = (Pkcs11.char_array_to_ulong class_templ.(0).Pkcs11.value) in
    let myclass = Pkcs11.match_cKO_value myclass in
    let msg = (match myclass with
      | "cKO_DATA" -> "Sorry CKO_DATA not supported yet."
      | "cKO_SECRET_KEY" -> print_myclass_short "Secret key"; print_secret_key_attrs session_ object_; ""
      | "cKO_PUBLIC_KEY" -> print_myclass_short "Public key"; print_public_key_attrs session_ object_; ""
      | "cKO_CERTIFICATE" -> print_myclass_short "Certificate"; print_certificate_attrs session_ object_; ""
      | "cKO_PRIVATE_KEY" -> print_myclass_short "Private key"; print_private_key_attrs session_ object_; ""
      | "cKO_HW_FEATURE" -> print_myclass_short "Hardware feature"; "Sorry CKO_HW_FEATURE not supported yet."
      | "cKO_DOMAIN_PARAMETERS" -> print_myclass_short "Domain parameters"; print_dsa_domain_parameters_attrs session_ object_; ""
      | "cKO_MECHANISM" -> print_myclass_short "Mechanism"; "Sorry CKO_MECHANISM not supported yet."
      | _ -> failwith "Sorry unknown object type" ) in
    Printf.printf "%s" msg;
    (* Print additional information if requested *)
    print_additional_attributes session_ object_;
    ()
