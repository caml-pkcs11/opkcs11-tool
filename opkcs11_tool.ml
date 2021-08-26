(************************* MIT License HEADER ************************************
    Copyright ANSSI (2014-2015)
    Contributors : Ryad BENADJILA [ryad.benadjila@ssi.gouv.fr] and
    Thomas CALDERON [thomas.calderon@ssi.gouv.fr]

    This software is a computer program whose purpose is to offer CLI
    capabilities to administer and use PKCS#11 devices. It is similar to
    OpenSC's pkcs11-tool but offers a more complete feature set.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

    Except as contained in this notice, the name(s) of the above copyright holders
    shall not be used in advertising or otherwise to promote the sale, use or other
    dealings in this Software without prior written authorization.

 ----------------------
    Project: opkcs11-tool
    File:    opkcs11_tool.ml
************************** MIT License HEADER ***********************************)

open P11_common
open P11_crypto
open P11_objects
open P11_infos
open P11_templates
open Printf

let usage = "usage: " ^ Sys.argv.(0) ^ " [OPTIONS]"

let myPrintf format_string =
  if (!do_quiet) = true then
       (Printf.eprintf format_string)
  else
       (Printf.printf format_string)

(* Basic password prompt *)
let read_password msg =
  myPrintf "%s" msg;
  let term_init = Unix.tcgetattr Unix.stdin in
  let term_no_echo = { term_init with Unix.c_echo = false; } in
  Unix.tcsetattr Unix.stdin Unix.TCSANOW term_no_echo;
  let password = read_line () in
  Unix.tcsetattr Unix.stdin Unix.TCSAFLUSH term_init;
  myPrintf "\n";
  (password)

IFDEF OCAML_NO_BYTES_MODULE THEN
let my_read_file my_data =
    read_file ~set_binary:true my_data
ENDIF
IFNDEF OCAML_NO_BYTES_MODULE THEN
let my_read_file my_data =
    (Bytes.to_string (read_file ~set_binary:true my_data))
ENDIF

let check_input_data my_data message =
    let data = (match !my_data with
         | "" -> failwith message
         | "-" -> input_line stdin
         | _ -> my_read_file !my_data) in
    data

let speclist = [
    ("-module", Arg.Set_string module_string, ": Specify the module to load (mandatory)");
    ("-I", Arg.Set do_show_info, ": Show global token information");
    ("-L", Arg.Set do_show_slots, ": List available slots");
    ("-T", Arg.Set do_show_token, ": List slots with tokens");
    ("-M", Arg.Set do_show_mechs, ": List mechanisms supported by the token");
    ("-O", Arg.Set do_show_objects, ": Show objects on token");
    ("-l", Arg.Set do_login, ": Log into the token first");
    ("-d", Arg.Set do_hash, ": Digest (hash) some data");
    ("-s", Arg.Set do_sign, ": Sign some data");
    ("-v", Arg.Set do_verify, ": Perform onboard verify");
    ("-q", Arg.Set do_quiet, ": Perform quietly, output crypto results on stdout, others on stderr");
    ("-verify", Arg.Set_string data_to_verify, ": Signed input to verify");
    ("-enc", Arg.Set do_encrypt, ": Encrypt some data");
    ("-dec", Arg.Set do_decrypt, ": Decrypt some data");
    ("-wrap", Arg.Set do_wrap, ": Wrap a key (use -search-attributes to find a key to wrap and -wrap-attributes for the wrapping key");
    ("-unwrap", Arg.Set do_unwrap, ": Unwrap a key (use -wrap-attributes to find the unwrapping key and -attributes for the expected attributes of the resulting object");
    ("-w", Arg.Set do_write, ": Create an object");
    ("-c", Arg.Set do_copy_objects, ": Copy an object with new attributes");
    ("-init-token", Arg.Set do_init_token, ": Initialize the token, its label and its SO PIN (use with -label and -so-pin)");
    ("-init-pin", Arg.Set do_init_pin, ": Initialize the USER PIN, (use with -pin and -so-pin)");
    ("-login-type", Arg.Set_string login_type, ": Specify login type ('so', 'user', default 'user')");
    ("-change-pin", Arg.Set do_change_pin, ": Change the PIN, (use with -login-type");
    ("-unblock-pin", Arg.Set do_unblock_pin, ": Unblock the PIN (unlogged session, oldPin is PUK)");
    ("-so-pin", Arg.Set_string so_pin, ": Specify the SO PIN");
    ("-type", Arg.Set_string object_type, ": Specify the object type (cert, pubkey, privkey)");
    ("-in", Arg.Set_string input_data, ": Specify the input data");
    ("-out", Arg.Set_string output_data, ": Specify the output data");
    ("-mech", Arg.Set_string mech_string, ": Specify the mechanism to use");
    ("-slot", Arg.Set_string slot_id, ": Specify the slot ID to use");
    ("-pin", Arg.Set_string user_pin, ": Supply User PIN on the command line");
    ("-env-pin", Arg.Set user_pin_env, ": User PIN is fetched from environment variable (-pin is the variable)");
    ("-label", Arg.String object_label_func, ": Supply object label (in ASCII) to filter objects");
    ("-id", Arg.String object_id_func, ": Supply object id (in hexadecimal) to filter objects");
    ("-maxobjects", Arg.Set_string max_objects_string, ": Supply maximum number of object to deal with (default is all objects on the token)"); 
    ("-destroy", Arg.Set do_destroy, ": Toggle to destroy objects (label mandatory)");
    ("-destroy-all", Arg.Set do_destroy_all, ": Toggle to destroy ALL objects");
    ("-keypairgen", Arg.Set do_key_gen, ": Toggle to create a key pair");
    ("-keypairsize", Arg.Set_string key_pair_size, ": Supply the size of RSA modulus (size in bits)");
    ("-mechparams", Arg.Set_string mech_params, ": Supply the parameters of the mechanism (to be used during a key generation or other operations)");
    ("-mgftype", Arg.Set_string mgf_type, ": Supply the mgf parameter you would like to use (OAEP only, default to sha1 if unspecified)");
    ("-curve-name", Arg.Set_string curve_name, ": Supply the namedCurve when generating your EC key pair (default to prime256v1)");
    ("-keygen", Arg.Set do_sym_key_gen, ": Toggle to create a symmetric key");
    ("-keysize", Arg.Set_string key_size, ": ");
    ("-setattributes", Arg.Set do_set_attributes, ": Set attributes on objects found with a search template, provided in another template");
    ("-search-attributes", Arg.Set_string search_attributes_string, ": Supply the search attributes in the form of a string with comma separated attributes in hexadecimal or in ASCII if it is between quotes, for example \"CKA_ID=0123, CKA_LABEL=\"\", CKA_MODULUS=ABCDEF...\"");
    ("-wrap-attributes", Arg.Set_string wrap_attributes_string, ": Supply the attributes to find a wrapping key, syntax identical to -search-attributes");
    ("-attributes", Arg.Set_string set_attributes_string, ": Supply the attributes in the form of a string with comma separated attributes in hexadecimal or in ASCII if it is between quotes, for example \"CKA_ID=0123, CKA_LABEL=\"\", CKA_MODULUS=ABCDEF...\"");
    ("-priv-attributes", Arg.Set_string set_priv_attributes_string, ": Supply the private key attributes to set during a key pair generation in the form of a string with comma separated attributes in hexadecimal or in ASCII if it is between quotes, for example \"CKA_ID=0123, CKA_LABEL=\"\", CKA_MODULUS=ABCDEF...\"");
    ("-pub-attributes", Arg.Set_string set_pub_attributes_string, ": Supply the public key attributes to set during a key pair generation in the form of a string with comma separated attributes in hexadecimal or in ASCII if it is between quotes, for example \"CKA_ID=0123, CKA_LABEL=\"\", CKA_MODULUS=ABCDEF...\"");
    ("-dump-attributes", Arg.Set_string dump_attributes_string, ": Supply additionnal CKA_* attributes to dump during a -O operation");
    ("-verbose", Arg.Set do_verbose, ": Be more verbose");
  ]


(*
      --derive                  Derive a secret key using another key and some data
      --login-type <arg>        Specify login type ('so', 'user', 'context-specific'; default:'user')
      --puk <arg>               Supply User PUK on the command line
      --new-pin <arg>           Supply new User PIN on the command line
  -c, --change-pin              Change User PIN
      --unlock-pin              Unlock User PIN (without '--login' unlock in logged in session; otherwise '--login-type' has to be 'context-specific')
      --application-id <arg>    Specify the application ID of the data object (use with --type data)
  -t, --test                    Test (best used with the --login or --pin option)
      --test-ec                 Test EC (best used with the --login or --pin option)
*)

let check_empty_string string_ error_msg =
    if (string_) = "" then
      begin
          myPrintf "%s" error_msg;
          exit 1;
      end;
    ()

(* Main program *)
let () =
  (* If we have zero arguments, print the help *)
  let _ = (if (Array.length Sys.argv) <= 1 then raise (Arg.Bad ("Bad argument: no argument provided ... Run with '-h' to get help"))) in
  (* Read the arguments *)
  Arg.parse
    speclist
    (fun x -> raise (Arg.Bad ("Bad argument: " ^ x)))
    usage;

    let _ = init_module !module_string in

    (* Initialize module *)
    let ret_value = Pkcs11.c_Initialize () in
    let _ = check_ret ret_value C_InitializeError false in

    (* Get max objects to deal with *)
    if compare !max_objects_string "" <> 0 then
      begin
        (* String to native int *)
        max_objects := (try Nativeint.of_string !max_objects_string with
          _ -> let s = Printf.sprintf "Error: provided maxobjects %s is not a proper integer" !max_objects_string in failwith(s));
      end;

    (* Show info *)
    if (!do_show_info) then
      begin
        let (ret_value, info_) = Pkcs11.c_GetInfo () in
        let _ = check_ret ret_value C_GetInfoError false in
        dbg_print !do_verbose "C_GetInfo" ret_value;
        print_info info_;
      end;

    (* Asked to print slots *)
    if (!do_show_slots) then
      begin
        (* Fetch slot count by passing 0n (present) 0n (count) *)
        let (ret_value, slot_list_, count) = Pkcs11.c_GetSlotList 0n 0n in
        let _ = check_ret ret_value C_GetSlotListError false in
        dbg_print !do_verbose "C_GetSlotList" ret_value;

        (* Fetch slot list by passing 0n count *)
        let (ret_value, slot_list_, count) = Pkcs11.c_GetSlotList 0n count in
        let _ = check_ret ret_value C_GetSlotListError false in
        dbg_print !do_verbose "C_GetSlotList" ret_value;

        Array.iter print_slots slot_list_;
      end;

      (* If no slot specified, try finding one with a token *)
      native_slot_id := (match !slot_id with
                    | "" -> let (ret_value, slot_list_, count) = Pkcs11.c_GetSlotList 1n 0n in
                        let _ = check_ret ret_value C_GetSlotListError false in
                        dbg_print !do_verbose "C_GetSlotList" ret_value;
                        if count = 0n then
                          begin
                          myPrintf "No slot with a token was found.\n";
                          exit 0;
                          end;

                        (* Fetch slot list by passing 0n count *)
                        let (ret_value, slot_list_, count) = Pkcs11.c_GetSlotList 1n count in
                        let _ = check_ret ret_value C_GetSlotListError false in
                        dbg_print !do_verbose "C_GetSlotList" ret_value;
                        myPrintf "Using slot %s.\n" (Nativeint.to_string slot_list_.(0));
                        slot_list_.(0)
                    | _ -> let (_, _, _) = Pkcs11.c_GetSlotList 0n 0n in
                            (* Some library requires a GetSlotList call (OpenSC)
                                in order to initialize internal structure and
                                slot_ids. This is why we perform a useless call
                                here *)
                                Nativeint.of_string !slot_id );
 
    let (ret_value, token_infos_) = Pkcs11.c_GetTokenInfo !native_slot_id in
    let _ = check_ret ret_value C_GetTokenInfoError false in
    dbg_print !do_verbose "C_GetTokenInfo" ret_value;

    if (check_bit_on token_infos_.Pkcs11.ck_token_info_flags Pkcs11.cKF_TOKEN_INITIALIZED) then
      begin
        token_initialized := true;
      end;
    if (check_bit_on token_infos_.Pkcs11.ck_token_info_flags Pkcs11.cKF_PROTECTED_AUTHENTICATION_PATH) then
      begin
        token_supports_protected_auth_path := true;
      end;


    (* Asked to print token infos *)
    if (!do_show_token) then
      begin
	print_token_info token_infos_;
      end;

    (* Asked to print mechanisms *)
    if (!do_show_mechs) then
      begin
        let mechanism_list_ = get_mechanism_list_for_slot !native_slot_id in
        let _ = Array.iter (print_mechanism_info !native_slot_id) mechanism_list_ in
        ()
      end;

    (* Init a token *)
    if (!do_init_token) then
      begin
        let token_label = (match !object_label_given with
            false -> failwith "Specifying a token label is mandatory"
            | _ -> !object_label ) in
        if compare !so_pin "" = 0 then
          begin
            so_pin := read_password "Enter SO PIN:";
          end;
        check_empty_string !so_pin "C_InitToken requires a SO PIN!.\n" ;
	    let ret_value = Pkcs11.c_InitToken !native_slot_id (Pkcs11.string_to_char_array !so_pin) (Pkcs11.string_to_char_array token_label) in
	    let _ = check_ret ret_value C_InitTokenError false in
	    dbg_print !do_verbose "C_InitToken" ret_value;
      end;

    if (!token_initialized) = false then
      begin
      myPrintf "Token is not initialized, further functions will fail\n";
      end;

    (* Change a PIN *)
    if (!do_change_pin) then
      begin
	let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
	let _ = check_ret ret_value C_OpenSessionError false in
	dbg_print !do_verbose "C_OpenSession" ret_value;

    let (log_type, pin, new_pin) = (match !login_type with
        | "user" ->
            if compare !user_pin "" = 0 then
              begin
                user_pin := read_password "Enter USER PIN:";
              end;
            let new_pin = read_password "Enter NEW USER PIN:" in
            (Pkcs11.cKU_USER, !user_pin, new_pin)

        | "so" ->
            if compare !so_pin "" = 0 then
              begin
                so_pin := read_password "Enter SO PIN:";
              end;
            let new_pin = read_password "Enter NEW SO PIN:" in
            (Pkcs11.cKU_SO, !so_pin, new_pin)

        | _ -> failwith "Unsupported login type") in

    check_empty_string pin (Printf.sprintf "Changing PIN for %s requires a PIN!.\n" !login_type);
    check_empty_string new_pin (Printf.sprintf "Changing PIN for %s requires a NEW PIN!.\n" !login_type) ;

    let ret_value = Pkcs11.c_Login session_ log_type (Pkcs11.string_to_char_array pin) in
    let _ = check_ret ret_value C_LoginError false in
    dbg_print !do_verbose "C_Login" ret_value;

    let ret_value = Pkcs11.c_SetPIN session_ (Pkcs11.string_to_char_array pin) (Pkcs11.string_to_char_array new_pin) in
    let _ = check_ret ret_value C_SetPINError false in
    dbg_print !do_verbose "C_SetPIN" ret_value;

    let ret_value = Pkcs11.c_CloseSession session_ in
	let _ = check_ret ret_value C_CloseSessionError false in
	dbg_print !do_verbose "C_CloseSession" ret_value;
    end;

    (* Unblock a PIN *)
    (* This follows OpenSC convention, user_pin_unblock_style =
       set_pin_in_unlogged_session *)
    if (!do_unblock_pin) then
      begin
	let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
	let _ = check_ret ret_value C_OpenSessionError false in
	dbg_print !do_verbose "C_OpenSession" ret_value;

    if compare !so_pin "" = 0 then
      begin
        so_pin := read_password "Enter SO PIN:";
      end;

    if compare !user_pin "" = 0 then
      begin
        user_pin := read_password "Enter NEW USER PIN:";
      end;

    check_empty_string !user_pin "Unblock PIN requires a NEW PIN!.\n";
    check_empty_string !so_pin "Unblock PIN requires a PUK (SO_PIN)!.\n";

    let ret_value = Pkcs11.c_SetPIN session_ (Pkcs11.string_to_char_array !so_pin) (Pkcs11.string_to_char_array !user_pin) in
    let _ = check_ret ret_value C_SetPINError false in
    dbg_print !do_verbose "C_SetPIN" ret_value;

    let ret_value = Pkcs11.c_CloseSession session_ in
	let _ = check_ret ret_value C_CloseSessionError false in
	dbg_print !do_verbose "C_CloseSession" ret_value;
    end;

    (* Init a PIN *)
    if (!do_init_pin) then
      begin
	let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
	let _ = check_ret ret_value C_OpenSessionError false in
	dbg_print !do_verbose "C_OpenSession" ret_value;

        if compare !so_pin "" = 0 then
          begin
            so_pin := read_password "Enter SO PIN:";
          end;
        if compare !user_pin "" = 0 then
          begin
            user_pin := read_password "Enter USER PIN:";
          end;
        check_empty_string !so_pin "C_InitPIN requires a SO PIN!.\n" ;
        check_empty_string !user_pin "C_InitPIN requires a USER PIN!.\n" ;

        let ret_value = Pkcs11.c_Login session_ Pkcs11.cKU_SO (Pkcs11.string_to_char_array !so_pin) in
        let _ = check_ret ret_value C_LoginError false in
        dbg_print !do_verbose "C_Login" ret_value;

        let ret_value = Pkcs11.c_InitPIN session_ (Pkcs11.string_to_char_array !user_pin) in
	let _ = check_ret ret_value C_InitTokenError false in
	dbg_print !do_verbose "C_InitToken" ret_value;

        let ret_value = Pkcs11.c_CloseSession session_ in
	let _ = check_ret ret_value C_CloseSessionError false in
	dbg_print !do_verbose "C_CloseSession" ret_value;
      end;

    (* Get an attribute array if one is provided *)
    (* The search filtering attribute *)
    provided_search_attributes_array := (
      if compare !search_attributes_string "" <> 0 then
        (get_attributes_to_set !search_attributes_string)
      else
        [||]
    );
    provided_wrap_attributes_array := (
      if compare !wrap_attributes_string "" <> 0 then
        (get_attributes_to_set !wrap_attributes_string)
      else
        [||]
    );
    provided_attributes_array := (
      if compare !set_attributes_string "" <> 0 then
        (get_attributes_to_set !set_attributes_string)
      else
        [||]
    );
    provided_priv_attributes_array := (
      if compare !set_priv_attributes_string "" <> 0 then
        (get_attributes_to_set !set_priv_attributes_string)
      else
        [||]
    );
    provided_pub_attributes_array := (
      if compare !set_pub_attributes_string "" <> 0 then
        (get_attributes_to_set !set_pub_attributes_string)
      else
        [||]
    );

    (* Open a session "RO" *)
    let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id Pkcs11.cKF_SERIAL_SESSION in
    let _ = check_ret ret_value C_OpenSessionError false in
    dbg_print !do_verbose "C_OpenSession" ret_value;

    (* Perform login *)
    if (!do_login) then
      begin
      let pin_array = (
        if (!token_supports_protected_auth_path) = true then
          [||]
        else
          begin
          user_pin := (
            if (!user_pin_env) = true then
                (Sys.getenv !user_pin)
            else if compare !user_pin "" = 0 then
              (read_password "Enter PIN:")
            else
              !user_pin);
          check_empty_string !user_pin "You asked to authenticated but did not provide a PIN!.\n" ;
          (Pkcs11.string_to_char_array !user_pin)
          end
      ) in
        let ret_value = Pkcs11.c_Login session_ Pkcs11.cKU_USER pin_array in
        let _ = check_ret ret_value C_LoginError false in
        dbg_print !do_verbose "C_Login" ret_value;
        ()
      end;

    (* Find Objects and display attributes *)
    if (!do_show_objects) then
      begin
        (* If a label, id and template are given we base our search template on this *)
        let template = (
          if !object_label_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_LABEL ; Pkcs11.value = Pkcs11.string_to_char_array !object_label }|]
          else if !object_id_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_ID ; Pkcs11.value = Pkcs11.string_to_char_array !object_id }|]
          else
            [||]
        ) in
        let template = merge_templates template !provided_search_attributes_array in
        let (objects_, count_) =  find_objects session_ template !max_objects in
        myPrintf "%s objects found\n" (Nativeint.to_string count_);
        Array.iter (print_object_attributes session_)  objects_;
        ()
      end;

    (* Perform object destruction *)
    if (!do_destroy) then
      begin
        let _ = check_empty_string !user_pin "You asked to destroy an object without providing a PIN!.\n" in
        let template = (
          if !object_label_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_LABEL ; Pkcs11.value = Pkcs11.string_to_char_array !object_label }|]
          else if !object_id_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_ID ; Pkcs11.value = Pkcs11.string_to_char_array !object_id }|]
          else
            [||]
        ) in
        let template = merge_templates template !provided_search_attributes_array in
        let _ = destroy_object_with_template template in
        ()
      end;

    (* Perform COMPLETE object destruction *)
    if (!do_destroy_all) then
      begin
        check_empty_string !user_pin "You asked to destroy ALL objects without providing a PIN!.\n";
        let _ = destroy_all_objects () in
        ()
      end;

    (* Get key (pair) generation optional parameters as a char array *)
    if compare !mech_params "" <> 0 then
      begin
      provided_mech_params_array := Pkcs11.string_to_char_array (try Pkcs11.pack !mech_params with
        _ -> let s = Printf.sprintf "Error: provided mechanism parameters %s are not proper hexadecimal values" !mech_params in failwith s)
      end;

    (* Generate a key pair *)
    if (!do_key_gen) then
        begin
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        let label = (match !object_label_given with
            false -> None
            | _ -> Some !object_label ) in
        let id =  (match !object_id_given with
            false -> None
            | _ -> Some !object_id ) in

        (* Default keypairsize to 0n, let underlying functions handle that *)
        let the_key_size = (match !key_pair_size with
            | "" -> 0n
            | _ -> Nativeint.of_string !key_pair_size) in

        match !mech_string with
            | "EC"
            | "ec"
            | "ECC"
            | "ecc" ->
                let (pub_, priv_) = generate_ecc_key_pair_template !curve_name label id true in
                (* C_GenerateKeyPair for ECC, we'll try first using OID and if it fails
                    we'll derive the curve parameters from name and retry *)
                let pub_ = merge_templates pub_ !provided_pub_attributes_array in
                let priv_ = merge_templates priv_ !provided_priv_attributes_array in
                let continue_on_error = true in
                let (_, _, ret_value) = generate_ecc_key_pair session_ pub_ priv_ !provided_mech_params_array continue_on_error in
                let msg = Pkcs11.match_cKR_value ret_value in
                (match msg with
                    (* basic check, if successful or "typical error", do not ty
                       again *)
                      "cKR_OK" -> ()
                    | "cKR_TEMPLATE_INCONSISTENT" -> ()
                    | "cKR_TEMPLATE_INCOMPLETE" -> ()
                    (* OK, let's try again using explicit EC parameters *)
                    | _ -> myPrintf "C_GenerateKeyPair failed for ECC, trying explicit parameters\n";
                        let (pub_, priv_) = generate_ecc_key_pair_template !curve_name label id false in
                        let pub_ = merge_templates pub_ !provided_pub_attributes_array in
                        let priv_ = merge_templates priv_ !provided_priv_attributes_array in
                        (* fail on second error *)
                        let continue_on_error = false in
                        let (_, _, _) = generate_ecc_key_pair session_ pub_ priv_ !provided_mech_params_array continue_on_error in ())
            | "RSA"
            | "rsa" -> 
                if (compare the_key_size 0n = 0) then
                    begin
                    failwith "Please specify RSA asymmetric key pair size using -keypairsize\n"
                    end;
                let (pub_, priv_) = generate_rsa_key_pair_template the_key_size label id  in
                let pub_ = merge_templates pub_ !provided_pub_attributes_array in
                let priv_ = merge_templates priv_ !provided_priv_attributes_array in
                let (_, _, _) = generate_rsa_key_pair session_ pub_ priv_ !provided_mech_params_array in
                ()
            | "DSA"
            | "dsa" ->
                if (compare the_key_size 0n = 0) then
                    begin
                    failwith "Please specify DSA asymmetric key pair size using -keypairsize\n"
                    end;
                (* In this case, we assume that we generate some domain
                   parameters onboard and use feed them to the public key
                   template for the DSA generation *)
                let (obj_dsa_params, ret_value) = generate_dsa_domain_parameters session_ label the_key_size in
                let (pub_, priv_) = generate_dsa_key_pair_template session_ obj_dsa_params label id  in
                let pub_ = merge_templates pub_ !provided_pub_attributes_array in
                let priv_ = merge_templates priv_ !provided_priv_attributes_array in
                let (_, _, _) = generate_dsa_key_pair session_ pub_ priv_ !provided_mech_params_array in
                ()
            | _ -> 
              (* If raw public and private key templates have been provided, we perform a raw generate key pair *)
              if (compare !provided_pub_attributes_array [||] <> 0) && (compare !provided_priv_attributes_array [||] <> 0)
                 && (compare !mech_string "" <> 0) then
                 let pub_ = (if !object_label_given = true then [|{Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = Pkcs11.string_to_char_array !object_label}|] else [||]) in
                 let pub_ = (if !object_id_given = true then Array.concat [pub_; [|{Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = Pkcs11.string_to_char_array !object_id}|]] else pub_) in
                 let pub_ = (if compare the_key_size 0n <> 0 then Array.concat [pub_; [| {Pkcs11.type_ = Pkcs11.cKA_MODULUS_BITS; Pkcs11.value = (Pkcs11.int_to_ulong_char_array the_key_size)} |]] else pub_) in
                 let pub_ = merge_templates pub_ !provided_pub_attributes_array in
                 let priv_ = (if !object_label_given = true then [|{Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = Pkcs11.string_to_char_array !object_label}|] else [||]) in
                 let priv_ = (if !object_id_given = true then Array.concat [priv_; [|{Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = Pkcs11.string_to_char_array !object_id}|]] else priv_) in
                 let priv_ = merge_templates priv_ !provided_priv_attributes_array in
                 let mech = match_string_to_keygenpair_mech_value !mech_string in 
                 let (ret_value, _, _) = Pkcs11.c_GenerateKeyPair session_ {Pkcs11.mechanism = mech; Pkcs11.parameter = !provided_mech_params_array} pub_ priv_ in
                 let _ = check_ret ret_value C_GenerateKeyPairError false in
                 myPrintf "C_GenerateKeyPair ret: %s\n" (Pkcs11.match_cKR_value ret_value);
              else
                (* Else, we fail *)
                failwith "Unsupported key pair generation mechanism, RSA or custom provided mechanisms/templates only"
        end;

    (* Generate a summetric key *)
     if (!do_sym_key_gen) then
        begin
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        (* FIXME: future should support other key-types and adapt *)
        let the_key_size = (match !key_size with
            | "" -> let _ = myPrintf "No symmetric key size specified, adapting to provided mechanism\n" in
                    let ks = 
                      (match !mech_string with
                       | ("AES" |"aes") -> 128n
                       | ("DES" |"des") -> 64n
                       | ("DES2"|"des2") -> 128n
                       | ("DES3"|"des3") -> 192n
                       | _ -> 
                         (* If attributes have been provided, we possibly don't care *)
                         if (compare !provided_attributes_array [||] <> 0) then
                           (0n)
                         else
                           (* else we fail *)
                           if compare !mech_string "generic" = 0 then
                             failwith "Error: you have asked for a generic secret key without providing a key size"
                           else
                             failwith "Error: you have provided an unknown symmetric key generation mechanism") in (ks)
            | _ -> Nativeint.of_string !key_size) in
        match !mech_string with
            | "AES"
            | "aes"
            | "DES"
            | "des"
            | "DES2"
            | "des2"
            | "DES3"
            | "des3"
            | "generic" ->
              (* Check the provided keysize *)
              let obj_label = (if !object_label_given = true then (Some !object_label) else (None)) in
              let obj_id = (if !object_id_given = true then (Some !object_id) else (None)) in              
              generate_symkey !mech_string the_key_size obj_label obj_id !provided_mech_params_array !provided_attributes_array session_
            | _ -> 
              (* If raw public and private key templates have been provided, we perform a raw generate key pair *)
              if (compare !provided_attributes_array [||] <> 0)
                 && (compare !mech_string "" <> 0) then
                let templ_ = (if !object_label_given = true then [|{Pkcs11.type_ = Pkcs11.cKA_LABEL; Pkcs11.value = Pkcs11.string_to_char_array !object_label}|] else [||]) in
                let templ_ = (if !object_id_given = true then Array.concat [templ_; [|{Pkcs11.type_ = Pkcs11.cKA_ID; Pkcs11.value = Pkcs11.string_to_char_array !object_id}|]] else templ_) in
                let templ_ = (if compare the_key_size 0n <> 0 then Array.concat [templ_; [| {Pkcs11.type_ = Pkcs11.cKA_VALUE_LEN; Pkcs11.value =  (Pkcs11.int_to_ulong_char_array (Nativeint.div the_key_size 8n))} |]] else templ_) in
                let templ_ = merge_templates templ_ !provided_attributes_array in                
                let mech = match_string_to_sym_key_gen_mech_value !mech_string in 
                let (ret_value, _) = Pkcs11.c_GenerateKey session_ {Pkcs11.mechanism = mech; Pkcs11.parameter = !provided_mech_params_array} templ_ in
                let _ = check_ret ret_value C_GenerateKeyError false in
                myPrintf "C_GenerateKey ret: %s\n" (Pkcs11.match_cKR_value ret_value);
              else
                (* Else, we fail *)
                failwith "Unsupported symmetric key generation mechanism, AES/DES/DES2/DES3 or custom provided mechanisms/templates only"
        end;

    (* Hash some data *)
    if (!do_hash) then
      begin
        let data = check_input_data input_data "Input data needs to be given to digest data" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_SHA1\n"; Pkcs11.cKM_SHA_1
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = [||]} in
        let (digest_) = digest_some_data session_ mech data in
        if (!do_quiet) = false then
            Pkcs11.print_hex_array digest_;
        if (compare !output_data "" <> 0) then
        begin
          myPrintf "Writing data to %s\n" (!output_data);
          write_file ~set_binary:true !output_data (Pkcs11.char_array_to_string digest_);
        end;
        ()
      end;

    let initial_search_template = (
          if !object_label_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_LABEL ; Pkcs11.value = Pkcs11.string_to_char_array !object_label }|]
          else if !object_id_given = true then
            [|{ Pkcs11.type_ =Pkcs11.cKA_ID ; Pkcs11.value = Pkcs11.string_to_char_array !object_id }|]
          else
            [||]
        ) in

    (* Sign some data *)
    if (!do_sign) then
      begin
        let data = check_input_data input_data "Input data needs to be given to sign data" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = [||]} in
        (* find a privkey to sign *)
        let template = initial_search_template in
        let template = templ_append template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY) in
        let template = templ_append template Pkcs11.cKA_SIGN Pkcs11.true_ in
        let template = merge_templates template !provided_search_attributes_array in

        let (objects_, count_) =  find_objects session_ template !max_objects in
        if (compare count_ 0n <> 0) then
        begin
          let (signed_) = sign_some_data session_ mech objects_.(0) data in
          myPrintf "Signed data (in hex): ";
          if (!do_quiet) = false then
            begin
            Pkcs11.print_hex_array signed_;
            end
          else
            begin
            (* Here, print on stdout, expected on QUIET mode *)
            Printf.printf "%s" (Pkcs11.char_array_to_string signed_);
            end;
          if (compare !output_data "" <> 0) then
          begin
            myPrintf "Writing data to %s\n" (!output_data);
            write_file ~set_binary:true !output_data (Pkcs11.char_array_to_string signed_);
          end;
          ()
        end
        else
          failwith "No private key found to sign"
      end;

    (* Verify some data *)
    if (!do_verify) then
      begin
        let data = check_input_data input_data "Input data needs to be given to verify data" in
        let data_verif = check_input_data data_to_verify "Signed input data needs to be given to verify signature" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = [||]} in
        (* find a pubkey to verify *)
        let template = initial_search_template in
        let template = templ_append template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PUBLIC_KEY) in
        let template = templ_append template Pkcs11.cKA_VERIFY Pkcs11.true_ in
        let template = merge_templates template !provided_search_attributes_array in
        let (objects_, count_) =  find_objects session_ template !max_objects in
        if (compare count_ 0n <> 0) then
        begin
          let verify_ = verify_some_data session_ mech objects_.(0) data data_verif in
          myPrintf "Verify operation returned : %s\n" (Pkcs11.match_cKR_value verify_);
          ()
        end
        else
          failwith "No public key found to verify"
      end;

    (* Encrypt some data *)
    if (!do_encrypt) then
      begin
        let data = check_input_data input_data "Input data needs to be given to encrypt data" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = !provided_mech_params_array} in
        (* find a pubkey to encrypt *)
        let template = initial_search_template in
        let template = templ_append template Pkcs11.cKA_ENCRYPT Pkcs11.true_ in
        let template = merge_templates template !provided_search_attributes_array in
        let (objects_, count_) =  find_objects session_ template !max_objects in
        if (compare count_ 0n <> 0) then
        begin
          let (encrypted_) = encrypt_some_data session_ mech objects_.(0) data in
          myPrintf "Encrypted data (in hex): ";
          if (!do_quiet) = false then
            begin
            Pkcs11.print_hex_array encrypted_;
            end
          else
            begin
            (* Here, print on stdout, expected on QUIET mode *)
            Printf.printf "%s" (Pkcs11.char_array_to_string encrypted_);
            end;
          if (compare !output_data "" <> 0) then
          begin
            myPrintf "Writing data to %s\n" (!output_data);
            write_file ~set_binary:true !output_data (Pkcs11.char_array_to_string encrypted_);
          end;
          ()
        end
        else
          failwith "No key found to encrypt"
      end;

    (* Decrypt some data *)
    if (!do_decrypt) then
      begin
        let data = check_input_data input_data "Input data needs to be given to decrypt data" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = !provided_mech_params_array} in
        (* find a privkey to decrypt *)
        let template = initial_search_template in
        let template = templ_append template Pkcs11.cKA_CLASS (Pkcs11.int_to_ulong_char_array Pkcs11.cKO_PRIVATE_KEY) in
        let template = templ_append template Pkcs11.cKA_DECRYPT Pkcs11.true_ in
        let template = merge_templates template !provided_search_attributes_array in
        let (objects_, count_) =  find_objects session_ template !max_objects in
        if (compare count_ 0n <> 0) then
        begin
          let (decrypted_) = decrypt_some_data session_ mech objects_.(0) data in
          myPrintf "Decrypted data (in hex): ";
          if (!do_quiet) = false then
            begin
            Pkcs11.print_hex_array decrypted_;
            end
          else
            begin
            (* Here, print on stdout, expected on QUIET mode *)
            Printf.printf "%s" (Pkcs11.char_array_to_string decrypted_);
            end;
          begin
            myPrintf "Writing data to %s\n" (!output_data);
            write_file ~set_binary:true !output_data (Pkcs11.char_array_to_string decrypted_);
          end;
          ()
        end
        else
          failwith "No key found to decrypt"
      end;

    (* Perform object creation *)
    if (!do_write) then
      begin
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        let data = (
          match !input_data with
            | "" -> 
                (* If no file is provided, attributes must be provided *)
                if compare !provided_attributes_array [||] = 0 then
                  failwith "Input data or a non empty creation template needs to be specified for object creation"
                else
                  ("")
            | _ -> (my_read_file !input_data)
        ) in
        let label = (match !object_label_given with
            false -> None
            | _ -> Some !object_label ) in
        let id = (match !object_id_given with
            false -> None
            | _ -> Some !object_id ) in
        match !object_type with
            | "cert" ->
                let (_, _) = create_cert_object session_ label id data !input_data !provided_attributes_array in
                ()
            | "pubkey" ->
                let (_, _) = create_pubkey_object session_ label id data !provided_attributes_array in
                ()
            | "privkey" -> 
                let (_, _) = create_privkey_object session_ label id data !provided_attributes_array in
                ()
            | "secretkey" ->
                let (_, _) = create_secretkey_object session_ label id data !provided_attributes_array in
                ()
            | _ -> failwith "Object type can only be cert|pubkey|privkey|secretkey"
      end;

    (* Perform setting attributes value *)
    (* TODO: complete this *)
    if (!do_set_attributes) then
      begin
        (* Open a RW session *)
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        (* First, we find all the objects according to the search templates *)
        let (objects_, count_) =  find_objects session_ !provided_search_attributes_array !max_objects in 
        (* Once the objects have been found, apply the given "set attributes" array *)
        Array.iter (
          fun objecth ->
            let ret_value = Pkcs11.c_SetAttributeValue session_ objecth !provided_attributes_array in
            let _ = check_ret ret_value C_SetAttributeValueError false in
            dbg_print !do_verbose "C_SetAttributeValue" ret_value;
        ) objects_
      end;

    (* Copy an object with new attributes *)
    if (!do_copy_objects) then
      begin
        (* Make a copy of all the objects matching the search attributes with the given attributes *)
        (* Open a RW session *)
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        (* First, we find all the objects according to the search templates *)
        let (objects_, count_) =  find_objects session_ !provided_search_attributes_array !max_objects in 
        (* Once the objects have been found, make a copy of the object with the given "set attributes" array *)
        Array.iter (
          fun objecth ->
            let (ret_value, _) = Pkcs11.c_CopyObject session_ objecth !provided_attributes_array in
            let _ = check_ret ret_value C_CopyObjectError false in
            dbg_print !do_verbose "C_CopyObject" ret_value;
        ) objects_       
      end;

    (* Wrap an object *)
    if (!do_wrap) then
      begin
        (* Make a copy of all the objects matching the search attributes with the given attributes *)
        (* Open a RW session *)
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = !provided_mech_params_array} in

        (* First, we find all the objects according to the search templates *)
        let (wrapping_keys, count_) =  find_objects session_ !provided_wrap_attributes_array 1n in 
	  if compare count_ 0n = 0 then
            failwith "No wrapping key could be found given your search template"
          else
            begin
              let (objects_, count_) =  find_objects session_ !provided_search_attributes_array 1n in 
                if compare count_ 0n = 0 then
                  failwith "No object was found to be wrapped given your search template"
                else
                    begin
                    let wrapped_key_ = wrap_key session_ mech wrapping_keys.(0) objects_.(0) in
                    myPrintf "Wrapped key (in hex): ";
                    if (!do_quiet) = false then
                        begin
                        Pkcs11.print_hex_array wrapped_key_;
                        end
                    else
                        begin
                        (* Here, print on stdout, expected on QUIET mode *)
                        Printf.printf "%s" (Pkcs11.char_array_to_string wrapped_key_);
                        end;
                    if (compare !output_data "" <> 0) then
                      begin
                        myPrintf "Writing data to %s\n" (!output_data);
                        write_file ~set_binary:true !output_data (Pkcs11.char_array_to_string wrapped_key_);
                        ()
                      end;
                    end;
            end;
      end;

    if (!do_unwrap) then
      begin
        (* Make a copy of all the objects matching the search attributes with the given attributes *)
        (* Open a RW session *)
        let (ret_value, session_) = Pkcs11.c_OpenSession !native_slot_id (Nativeint.logor Pkcs11.cKF_SERIAL_SESSION Pkcs11.cKF_RW_SESSION) in
        let _ = check_ret ret_value C_OpenSessionError false in
        dbg_print !do_verbose "C_OpenSession" ret_value;

        let data = check_input_data input_data "Input data needs to be given to unwrap key" in
        let mech_type = (match !mech_string with
            | "" -> myPrintf "No specified mechanism, falling back to CKM_RSA_PKCS\n"; Pkcs11.cKM_RSA_PKCS
            | _ -> Pkcs11.string_to_cKM_value !mech_string ) in
        let mech = { Pkcs11.mechanism = mech_type; Pkcs11.parameter = !provided_mech_params_array} in

        (* First, we find all the objects according to the search templates *)
        let (wrapping_keys, count_) =  find_objects session_ !provided_wrap_attributes_array 1n in 
	  if compare count_ 0n = 0 then
            failwith "No unwrapping key could be found given your search template"
          else
            begin
              let _ = unwrap_key session_ mech wrapping_keys.(0) data !provided_attributes_array in
              ()
              end;
      end;

    let ret_value = Pkcs11.c_CloseAllSessions !native_slot_id in
    let _ = check_ret ret_value C_CloseAllSessionsError false in
    dbg_print !do_verbose "C_CloseAllSessions" ret_value;

    let ret_value = Pkcs11.c_Finalize () in
    let _ = check_ret ret_value C_FinalizeError false in
    dbg_print !do_verbose "C_Finalize" ret_value;

    ()
;;
