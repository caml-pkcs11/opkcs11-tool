open Printf
open Ecc_helper

exception C_InitializeError
exception C_FinalizeError
exception C_GetInfoError
exception C_WaitForSlotEventError
exception C_GetSlotListError
exception C_GetSlotListError
exception C_GetSlotInfoError
exception C_GetTokenInfoError
exception C_OpenSessionError
exception C_CloseSessionError
exception C_CloseAllSessionsError
exception C_GetSessionInfoError
exception C_LoginError
exception C_LogoutError
exception C_GetMechanismListError
exception C_GetMechanismInfoError
exception C_InitTokenError
exception C_InitTokenError
exception C_InitPINError
exception C_InitPINError
exception C_SetPINError
exception C_SetPINError
exception C_SeedRandomError
exception C_GenerateRandomError
exception C_FindObjectsInitError
exception C_FindObjectsError
exception C_FindObjectsFinalError
exception C_GenerateKeyError
exception C_GenerateKeyPairError
exception C_CreateObjectError
exception C_CopyObjectError
exception C_DestroyObjectError
exception C_GetAttributeValueError
exception C_SetAttributeValueError
exception C_GetObjectSizeError
exception C_WrapKeyError
exception C_UnwrapKeyError
exception C_DeriveKeyError
exception C_DigestInitError
exception C_DigestError
exception C_DigestUpdateError
exception C_DigestKeyError
exception C_DigestFinalError
exception C_SignInitError
exception C_SignRecoverInitError
exception C_SignError
exception C_SignRecoverError
exception C_SignUpdateError
exception C_SignFinalError
exception C_VerifyInitError
exception C_VerifyRecoverInitError
exception C_VerifyError
exception C_VerifyRecoverError
exception C_DecryptError
exception C_VerifyUpdateError
exception C_VerifyFinalError
exception C_EncryptInitError
exception C_EncryptError
exception C_EncryptError
exception C_EncryptUpdateError
exception C_EncryptUpdateError
exception C_DigestEncryptUpdateError
exception C_DigestEncryptUpdateError
exception C_SignEncryptUpdateError
exception C_SignEncryptUpdateError
exception C_EncryptFinalError
exception C_EncryptFinalError
exception C_DecryptInitError
exception C_DecryptError
exception C_DecryptError
exception C_DecryptUpdateError
exception C_DecryptUpdateError
exception C_DecryptFinalError
exception C_DecryptFinalError
exception C_DecryptDigestUpdateError
exception C_DecryptDigestUpdateError
exception C_DecryptVerifyUpdateError
exception C_DecryptVerifyUpdateError
exception C_GetFunctionStatusError
exception C_CancelFunctionError
exception C_GetOperationStateError
exception C_GetOperationStateError
exception C_SetOperationStateError

exception UnsupportedRSAKeySize
exception UnsupportedDSAKeySize
exception UnsupportedSymmetricKeySize
exception UnsupportedSymmetricKeyMechanism

exception UnknownPKCS11Attibute of string
exception PKCS11AttributeBadFormat of string

let do_show_info = ref false
let do_show_slots = ref false
let do_show_token = ref false
let do_show_mechs = ref false
let do_show_objects = ref false
let do_init_token = ref false
let do_init_pin = ref false
let do_change_pin = ref false
let do_login = ref false
let do_destroy = ref false
let do_destroy_all = ref false
let do_hash = ref false
let do_sign = ref false
let do_verify = ref false
let do_encrypt = ref false
let do_decrypt = ref false
let do_wrap = ref false
let do_unwrap = ref false
let do_verbose = ref false
let module_string = ref ""
let mech_string = ref ""
let mgf_type = ref ""
let curve_name = ref ""
let login_type = ref "user"
let user_pin = ref ""
let so_pin = ref ""
let slot_id = ref ""
let do_key_gen = ref false
let do_sym_key_gen = ref false
let do_write = ref false
let input_data = ref ""
let data_to_verify = ref ""
let output_data = ref ""
let object_type = ref ""
let key_pair_size = ref ""
let key_pair_type = ref ""
let max_objects_string = ref ""
let max_objects = ref Nativeint.minus_one
let native_slot_id = ref 0n
let rand_len = ref ""
let pub_template = ref ""
let priv_template = ref ""
let token_initialized = ref false
let do_set_attributes = ref false
let dump_attributes_string = ref ""
let do_copy_objects = ref false

let object_label = ref ""
let object_label_given = ref false
let object_label_func in_string = 
  object_label := in_string;
  object_label_given := true

let object_id = ref ""
let object_id_given = ref false
let object_id_func in_string = 
  object_id := (try Pkcs11.pack in_string with 
    _ -> let s = Printf.sprintf "Error: provided object ID %s is not a proper hexadecimal value\n" in_string in failwith s);
  object_id_given := true

let key_size = ref ""

let search_attributes_string = ref ""
let wrap_attributes_string = ref ""
let set_attributes_string = ref ""
let set_priv_attributes_string = ref ""
let set_pub_attributes_string = ref ""

let provided_search_attributes_array : Pkcs11.ck_attribute array ref = ref [||]
let provided_wrap_attributes_array : Pkcs11.ck_attribute array ref = ref [||]
let provided_attributes_array : Pkcs11.ck_attribute array ref = ref [||]
let provided_priv_attributes_array : Pkcs11.ck_attribute array ref = ref [||]
let provided_pub_attributes_array : Pkcs11.ck_attribute array ref = ref [||]

let mech_params = ref ""
let provided_mech_params_array : char array ref = ref [||]

let dbg_print debug fun_name ret =
  if debug = true then
    printf "%s: returned %s\n" fun_name (Pkcs11.match_cKR_value ret);
  ()

let read_file ?set_binary:(bin=false) f =
  let ic = open_in f in
  set_binary_mode_in ic bin;
  let n = in_channel_length ic in
  let s = String.create n in
  really_input ic s 0 n;
  close_in ic;
  (s)

let write_file ?set_binary:(bin=false) f out_string =
  let oc = open_out f in
  set_binary_mode_out oc bin;
  output_string oc out_string;
  (close_out oc)

(* Attributes types *)
let cK_BOOL = 0n
let cK_CHAR_PTR = 1n
let cK_STRING = 2n
let cK_INTEGER = 3n
let cK_CKC = 4n
let cK_CKM = 5n
let cK_CKF = 6n
let cK_CKO = 7n
let cK_CKK = 8n

(* A few macro for attributes *)
  
let attr_decrypt = { Pkcs11.type_ =Pkcs11.cKA_DECRYPT ; Pkcs11.value = Pkcs11.true_ }
let attr_encrypt = { Pkcs11.type_ =Pkcs11.cKA_ENCRYPT ; Pkcs11.value = Pkcs11.true_ }
let attr_wrap = { Pkcs11.type_ =Pkcs11.cKA_WRAP ; Pkcs11.value = Pkcs11.true_ }
let attr_unwrap = { Pkcs11.type_ =Pkcs11.cKA_UNWRAP ; Pkcs11.value = Pkcs11.true_ }
let attr_decryptf = { Pkcs11.type_ =Pkcs11.cKA_DECRYPT ; Pkcs11.value = Pkcs11.false_ }
let attr_encryptf = { Pkcs11.type_ =Pkcs11.cKA_ENCRYPT ; Pkcs11.value = Pkcs11.false_ }
let attr_wrapf = { Pkcs11.type_ =Pkcs11.cKA_WRAP ; Pkcs11.value = Pkcs11.false_ }
let attr_unwrapf = { Pkcs11.type_ =Pkcs11.cKA_UNWRAP ; Pkcs11.value = Pkcs11.false_ }
let attr_sensitive = { Pkcs11.type_ =Pkcs11.cKA_SENSITIVE ; Pkcs11.value = Pkcs11.true_ }
let attr_sensitivef = { Pkcs11.type_ =Pkcs11.cKA_SENSITIVE ; Pkcs11.value = Pkcs11.false_ }
let attr_always_sensitive = { Pkcs11.type_ =Pkcs11.cKA_ALWAYS_SENSITIVE ; Pkcs11.value = Pkcs11.true_ }
let attr_always_sensitivef = { Pkcs11.type_ =Pkcs11.cKA_ALWAYS_SENSITIVE ; Pkcs11.value = Pkcs11.false_ }
let attr_extractable = { Pkcs11.type_ =Pkcs11.cKA_EXTRACTABLE ; Pkcs11.value = Pkcs11.true_ }
let attr_extractablef = { Pkcs11.type_ =Pkcs11.cKA_EXTRACTABLE ; Pkcs11.value = Pkcs11.false_ }
let attr_never_extractable = { Pkcs11.type_ =Pkcs11.cKA_NEVER_EXTRACTABLE ; Pkcs11.value = Pkcs11.true_ }
let attr_never_extractablef = { Pkcs11.type_ =Pkcs11.cKA_NEVER_EXTRACTABLE ; Pkcs11.value = Pkcs11.false_ }
let attr_token = { Pkcs11.type_ =Pkcs11.cKA_TOKEN ; Pkcs11.value = Pkcs11.true_ }
let attr_tokenf = { Pkcs11.type_ =Pkcs11.cKA_TOKEN ; Pkcs11.value = Pkcs11.false_ }

let template_token_wd = [| attr_wrap ; attr_decrypt ; attr_token |] 
let template_session_wd = [| attr_wrap ; attr_decrypt ; attr_tokenf |] 
let template_token_ue = [| attr_unwrap ; attr_encrypt ; attr_token |] 
let template_session_ue = [| attr_unwrap ; attr_encrypt ; attr_tokenf |] 
let template_sensitive_conflict = [| attr_sensitivef ; attr_always_sensitive |]  
let template_extractable_conflict = [| attr_extractable ; attr_never_extractable |]     
let template_wu =  [| attr_wrap ; attr_unwrap |] 

let find_existing_attribute attributes attribute =
  let check = List.filter (fun a -> compare a.Pkcs11.type_ attribute.Pkcs11.type_ = 0) (Array.to_list attributes) in
  if compare (List.length check) 0 = 0 then
    (false)
  else
    (true)

(* The following function appends to new_attributes the attributes in old_attributes that are not defined in new_attributes *)
let merge_templates old_attributes new_attributes =
  (* Remove current object attributes from the new attributes *)
  let purged_attributes = Array.fold_left (
    fun new_array a ->
      if find_existing_attribute new_attributes a = false then
        (Array.append new_array [|a|])
      else
        (new_array)
  ) [||] old_attributes in
  (* Merge the two arrays *)
  let full_list_attributes = Array.append purged_attributes new_attributes in
  (full_list_attributes)


(* Append one element to template array *)
let templ_append template type_ value_ =
    let template = Array.append template [| { Pkcs11.type_ = type_; Pkcs11.value = value_}|] in
    (template)

(* Append one string element to template array *)
let append_some_value_to_template type_ value_ template =
    let (template) = match value_ with
        None -> (template)
        | Some x  -> (templ_append template type_ (Pkcs11.string_to_char_array x)) in
    (template)

(* Append one string element to template array tuple *)
let append_rsa_template type_ value_ pub_template priv_template =
    let (pub_template, priv_template) = match value_ with
        None -> (pub_template, priv_template)
        | Some x  -> (templ_append pub_template type_ (Pkcs11.string_to_char_array x),
                        templ_append priv_template type_ (Pkcs11.string_to_char_array x)) in
    (pub_template, priv_template)

(* Call LoadModule to load C middleware *)
let init_module libname =
  if libname = "" then
    failwith "Libname cannot be empty"
  else
    (* We should check for LoadModule return values *)
    Pkcs11.c_LoadModule (Pkcs11.string_to_char_array libname)

(* Check return value and raise string on errors *)
let check_ret ret_value except continue =
    let msg = Pkcs11.match_cKR_value ret_value in
        match msg with
            "cKR_OK" -> msg
            | _ -> if continue = true then msg else failwith msg
            (*| _ -> if continue = true then msg else raise (except)*)

(* Retursn true if the result is cKR_OK, returns false otherwise *)
let check_ret_ok ret_value =
  Pkcs11.match_cKR_value ret_value = "cKR_OK" 


(* Function for checking if one element is in a list *)
let check_element_in_list the_list element =
   (* Find the element *)
  let found = try Some (List.find (fun a -> compare a element = 0) the_list) with
  (* If not found, return false *)
  Not_found -> (None) in
  if found = None
  then
    (false)
  else
    (true)

(* Function to get the intersection of two lists *)
let intersect l1 l2 =
  let intersection = List.filter (fun a -> check_element_in_list l2 a = true) l1 in
  (intersection)

let sprintf_bool_value_of_attribute value =
  match value with
  | v when v=0n -> "cKA_FALSE"
  | v when v=1n -> "cKA_TRUE"
  | _-> "not a boolean value!"
