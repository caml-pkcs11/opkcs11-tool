(* X509 handling *)
(* WARNING: this is a beta version    *)
(* Improvement and fixes are expected *)

exception X509_ASN1_parse_error of string


(*** Main fields ASN.1 definitions ***)
let version name = Asn1.Integer_R(name)

let certificate_serial_number name = Asn1.Integer_R(name)

let time name = Asn1.Option_R("", [ Asn1.GeneralizedTime_R(name, []); Asn1.UTCTime_R(name, []) ])

let validity name = Asn1.Sequence_R(name ^ ".Sequence", 1, 1, [
  time (name ^ ".notBefore");
  time (name ^ ".notAfter");
])

let unique_identifier name = Asn1.Bitstring_R(name, [])

let optional_parameters name = Asn1.Option_R("", 
  [ Asn1.Null_R(name ^ ".Null_parameters") ; Asn1.Any_R(name ^ ".Parameters") ]
)


let algorithm_identifier name = Asn1.Sequence_R(name ^ ".algorithmIdentifier", 1, 1, [
  Asn1.OID_R(name ^ ".algorithmIdentifier.OID", []);
  optional_parameters (name ^ ".algorithmIdentifier")
])

let subject_public_key_info name = Asn1.Sequence_R(name ^ ".subjectPublicKeyInfo", 1, 1, [
  algorithm_identifier (name ^ ".subjectPublicKeyInfo.algorithm");
  Asn1.Bitstring_R(name ^ ".subjectPublicKeyInfo.subjectPublicKey", [
    Asn1.Option_R("", [Pkcs1_8.rsa_public_key (name ^ ".subjectPublicKeyInfo.RSAPublicKey"); Asn1.Any_R(name ^ ".subjectPublicKeyInfo.AnyValue")])
  ])
])

let attribute_type name = Asn1.OID_R(name, [])

let attribute_value name = Asn1.Any_R(name)

let attribute_type_and_value name = Asn1.Sequence_R(name ^ ".AttributeTypeAndValue", 1, 1, [
  attribute_type (name ^ ".AttributeTypeAndValue.type");
  attribute_value (name ^ ".AttributeTypeAndValue.value");
])

let relative_distinguished_name name = Asn1.Set_R(name ^ ".RelativeDistinguishedName", 1, 100, [attribute_type_and_value (name ^ ".RelativeDistinguishedName")])

let rdn_sequence name = Asn1.Sequence_R(name ^ ".RDNSequence", 1, 100,  [relative_distinguished_name (name ^ ".RDNSequence")])

let naming n = Asn1.Option_R("", [ rdn_sequence (n ^ ".Name") ])

let displayText name = Asn1.Option_R("", [ Asn1.PrintableString_R(name, []); Asn1.IA5String_R(name, []); Asn1.UTF8String_R(name, []); Asn1.VisibleString_R(name, []); Asn1.BMPString_R(name, []); ])

let directoryString name = Asn1.Option_R("", [ Asn1.TeletexString_R(name, []); Asn1.PrintableString_R(name, []); Asn1.UniversalString_R(name, []); Asn1.UTF8String_R(name, []); Asn1.BMPString_R(name, []); ])

let anotherName name = Asn1.Sequence_R(name ^ ".AnotherName", 1, 1, [
  Asn1.OID_R(name ^ ".AnotherName.type-id", []);
  Asn1.Option_R("", [Asn1.Any_R(name ^ ".AnotherName.value"); Asn1.None_R;]);
])
 
let eDIPartyName name = Asn1.Sequence_R(name ^ ".EDIPartyName", 1, 1, [
  Asn1.Option_R("", [Asn1.SpecificTag_R("", 0, Asn1.Constructed, Asn1.Explicit, [directoryString name]); Asn1.None_R]);
  Asn1.SpecificTag_R("", 1, Asn1.Primitive, Asn1.Implicit, [directoryString name]);
])

(* TODO: ORAddress which is a complex extension *)
let oRAddress name = Asn1.Any_R(name)

let general_name name = Asn1.Option_R("", [
  Asn1.SpecificTag_R(name ^ ".otherName", 0, Asn1.Constructed, Asn1.Explicit, [anotherName (name ^ ".otherName")]);
  Asn1.SpecificTag_R("", 1, Asn1.Primitive, Asn1.Implicit, [Asn1.IA5String_R(name ^ ".rfc822Name", [])]);
  Asn1.SpecificTag_R("", 2, Asn1.Primitive, Asn1.Implicit, [Asn1.IA5String_R(name ^ ".dNSName", [])]);
  Asn1.SpecificTag_R("", 3, Asn1.Constructed, Asn1.Explicit, [oRAddress (name ^ ".x400Address")]);
  Asn1.SpecificTag_R("", 4, Asn1.Constructed, Asn1.Explicit, [naming (name ^ ".directoryName")]);
  Asn1.SpecificTag_R("", 5, Asn1.Constructed, Asn1.Explicit, [eDIPartyName (name ^ ".ediPartyName")]);
  Asn1.SpecificTag_R("", 6, Asn1.Primitive, Asn1.Implicit, [Asn1.IA5String_R(name ^ ".uniformResourceIdentifier", [])]);
  Asn1.SpecificTag_R("", 7, Asn1.Primitive, Asn1.Implicit, [Asn1.Octetstring_R(name ^ ".iPAddress", [])]);
  Asn1.SpecificTag_R("", 8, Asn1.Primitive, Asn1.Implicit, [Asn1.OID_R(name ^ ".registeredID", [])]);
])

let general_names name =  Asn1.Sequence_R("", 1, 100, [
  general_name name
])


(*** Helpers for Authority Key Identifier ***)
let authorityKeyIdentifier name = Asn1.Sequence_R("", 1, 1, [
  Asn1.Option_R("", [
    Asn1.SpecificTag_R("", 0, Asn1.Primitive, Asn1.Implicit, [Asn1.Octetstring_R(name ^ ".keyIdentifier", [])]);
    Asn1.None_R;
  ]);
  Asn1.Option_R("", [
    (* Should be general_names, but we use general_name because of IMPLICIT tagging *)
    Asn1.SpecificTag_R("", 1, Asn1.Constructed, Asn1.Implicit, [general_names (name ^ ".authorityCertIssuer")]);
    Asn1.None_R;
  ]);
  Asn1.Option_R("", [
    Asn1.SpecificTag_R("", 2, Asn1.Primitive, Asn1.Explicit, [certificate_serial_number (name ^ ".authorityCertSerialNumber")]);
    Asn1.None_R;
  ]);
])


(*** Helpers for CRL Distribution Points ***)
let distributionPointName name = Asn1.Option_R("", [
  Asn1.SpecificTag_R("", 0, Asn1.Constructed, Asn1.Implicit, [general_names (name ^ ".fullName")]);
  Asn1.SpecificTag_R("", 1, Asn1.Constructed, Asn1.Explicit, [relative_distinguished_name (name ^ ".nameRelativeToCRLIssuer")]);
])

let reasonFlags name = Asn1.Bitstring_R(name, []) 

let distributionPoint name = Asn1.Sequence_R("", 1, 1, [
  Asn1.Option_R("", [
    Asn1.SpecificTag_R("", 0, Asn1.Constructed, Asn1.Explicit, [distributionPointName (name ^ ".distributionPoint")]);
    Asn1.None_R;
  ]);
  Asn1.Option_R("", [
    Asn1.SpecificTag_R("", 1, Asn1.Constructed, Asn1.Explicit, [reasonFlags (name ^ ".reasons")]);
    Asn1.None_R;
  ]);   
  Asn1.Option_R("", [
    Asn1.SpecificTag_R("", 2, Asn1.Constructed, Asn1.Explicit, [general_names (name ^ ".cRLIssuer")]);
    Asn1.None_R;
  ]);
])

(*** Helpers for Certificate Policies ***)
let policyQualifierInfo name = Asn1.Sequence_R("", 1, 1, [
  Asn1.OID_R(name ^ ".policyQualifierId", Oids.get_oids_from_names ["cps"; "unotice"] Oids.oids);
  Asn1.Any_R(name ^ ".qualifier");
])


let policyQualifiers name = Asn1.Option_R("", [
  Asn1.Sequence_R("", 1, 100, [
    policyQualifierInfo name 
  ]);
  Asn1.None_R;
])

let policyIdentifier name = Asn1.OID_R(name, [])

let policyInformation name = Asn1.Sequence_R("", 1, 1, [
  policyIdentifier (name ^ ".policyIdentifier");
  policyQualifiers (name ^ ".policyQualifiers");
])

(*** Helpers for Authority Information Access ***)

(*********************** Extensions *********************)
(********************************************************)
let extension_generic_header name oids extension_data = Asn1.Sequence_R("", 1, 1, [
  Asn1.OID_R(name ^ ".extnID", Oids.get_oids_from_names oids Oids.oids); 
  Asn1.Option_R("", [Asn1.Boolean_R(name ^ ".critical"); Asn1.None_R]);
  Asn1.Octetstring_R(name ^ ".extnValue", extension_data);
])


(*** Subject Key Identifier ***)
let extension_subjectKeyIdentifier name = extension_generic_header (name ^ ".Extension_subjectKeyIdentifier") ["subjectKeyIdentifier"] [
  Asn1.Octetstring_R(name ^ ".Extension_subjectKeyIdentifier.SubjectKeyIdentifier", []);
]

(*** Authority Key Identifier ***)
let extension_authorityKeyIdentifier name = extension_generic_header (name ^ ".Extension_authorityKeyIdentifier") ["authorityKeyIdentifier"] [
  authorityKeyIdentifier (name ^ ".Extension_authorityKeyIdentifier");
]

(*** Key Usage ***)
let extension_keyUsage name = extension_generic_header (name ^ ".Extension_keyUsage") ["keyUsage"] [
  Asn1.Bitstring_R(name ^ ".Extension_keyUsage.KeyUsage", []);
]

(*** Extended Key Usage ***)
let extension_extKeyUsage name = extension_generic_header (name ^ ".Extension_extKeyUsage") ["extKeyUsage"] [
  Asn1.Sequence_R("", 1, 100, [
    Asn1.OID_R(name ^ ".Extension_extKeyUsage.KeyPurposeId", [])
  ])
]

(*** Subject Alternative Name ***)
let extension_subjectAltName name = extension_generic_header (name ^ ".Extension_subjectAltName") ["subjectAltName"] [
  general_names (name ^ ".Extension_subjectAltName");
]

(*** Authority Info Access ***)
let extension_authorityInfoAccess name = extension_generic_header (name ^ ".Extension_authorityInfoAccess") ["authorityInfoAccess"] [
  Asn1.Sequence_R("", 1, 100, [
    Asn1.Sequence_R("", 1, 1, [
      Asn1.OID_R(name ^ ".Extension_authorityInfoAccess.accessMethod", Oids.get_oids_from_names ["ad"; "caIssuers"; "ocsp"] Oids.oids);
      general_name (name ^ ".Extension_authorityInfoAccess.accessLocation");
    ])
  ])
]

(*** Basic Constraints ***)
let extension_basicConstraints name = extension_generic_header (name ^ ".Extension_basicConstraints") ["basicConstraints"] [
  Asn1.Sequence_R("", 1, 1, [
    Asn1.Option_R("", [Asn1.Boolean_R(name ^ ".Extension_basicConstraints.extnValue.cA"); Asn1.None_R ]);
    Asn1.Option_R("", [Asn1.Integer_R(name ^ ".Extension_basicConstraints.extnValue.pathLenConstraint"); Asn1.None_R ]);
  ])
]

(*** CRL Distribution Points ***)
let extension_cRLDistributionPoints name = extension_generic_header (name ^ ".Extension_cRLDistributionPoints") ["cRLDistributionPoints"] [
  Asn1.Sequence_R("", 1, 100, [
    distributionPoint (name ^ ".Extension_cRLDistributionPoints")
  ])
]

(*** Certificate Policies ***)
let extension_certificatePolicies name = extension_generic_header (name ^ ".Extension_certificatePolicies") ["certificatePolicies"] [
  Asn1.Sequence_R("", 1, 100, [
    policyInformation (name ^ ".Extension_certificatePolicies")
  ])
]




(* FIXME: should not exist, we should cover all the possible extensions *)
(*** Unkown extensions ***)
let extension_generic name = extension_generic_header (name ^ ".Extension_generic") [] [
  Asn1.Any_R(name ^ ".Extension_generic.AnyValue")
]

let extension name = 
  Asn1.Option_R("", [extension_keyUsage name; extension_extKeyUsage name; extension_subjectKeyIdentifier name; extension_subjectAltName name; extension_authorityInfoAccess name; extension_authorityKeyIdentifier name; extension_basicConstraints name; extension_cRLDistributionPoints name; extension_certificatePolicies name; extension_generic name ])

let extensions name = Asn1.Sequence_R("", 1, 100, [extension name])


(**************** Core certificate ************)
let tbs_certificate name = Asn1.Sequence_R(name ^ ".Sequence", 1, 1, [
  Asn1.SpecificTag_R(name ^ ".TBSCertificate.(0)", 0, Asn1.Constructed, Asn1.Explicit, [version (name ^ ".TBSCertificate.Version")]);
  certificate_serial_number (name ^ ".TBSCertificate.CertificateSerialNumber");
  algorithm_identifier (name ^ ".TBSCertificate.Signature");
  naming (name ^ ".TBSCertificate.Issuer");
  validity (name ^ ".TBSCertificate.Validity");
  naming (name ^ ".TBSCertificate.Subject");
  subject_public_key_info (name ^ ".TBSCertificate.SubjectPublicKeyInfo");    
  Asn1.Option_R("", [Asn1.SpecificTag_R(name ^ ".TBSCertificate.(1)", 1, Asn1.Constructed, Asn1.Explicit, [unique_identifier (name ^ ".TBSCertificate.(1).IssuerUniqueID")]); Asn1.None_R]);
  Asn1.Option_R("", [Asn1.SpecificTag_R(name ^ ".TBSCertificate.(2)", 2, Asn1.Constructed, Asn1.Explicit, [unique_identifier (name ^ ".TBSCertificate.(2).SubjectUniqueID")]); Asn1.None_R]);
  Asn1.Option_R("", [Asn1.SpecificTag_R(name ^ ".TBSCertificate.(3)", 3, Asn1.Constructed, Asn1.Explicit, [extensions (name ^ ".TBSCertificate.(3).Extensions")]); Asn1.None_R])
])

let x509_certificate_asn1_scheme =  Asn1.Sequence_R("X509Sequence", 1, 1, [
  tbs_certificate "X509Certificate";
  algorithm_identifier "X509Certificate.X509SignatureAlgorithm";
  Asn1.Bitstring_R("X509Certificate.X509Signature", [])])

(**** X509 class and helpers *****)
class x509_cert =
  object (s)
    val mutable version : (string*string) option = None 
    val mutable serial_number : (string*string) option = None
    val mutable issuer : (string*string) option = None
    val mutable validity_not_before : (string*string) option = None
    val mutable validity_not_after : (string*string) option = None
    val mutable subject : (string*string) option = None
    val mutable subject_public_key_info : (string*string) option = None
    val mutable subject_public_key : Pkcs1_8.pkcs_public_key option = None
    val mutable signature_algorithm : (string*string) option = None
    val mutable signature_params : (string*string) option = None
    val mutable signature : (string*string) option = None
    val mutable tbs : (string*string) option = None
    method get field = match field with
      | "version" -> (match version with | None -> ("", "") | Some(x) -> x)
      | "serial_number" -> (match serial_number with | None -> ("", "") | Some(x) -> x)
      | "issuer" -> (match issuer with | None -> ("", "") | Some(x) -> x)
      | "validity_not_before" -> (match validity_not_before with | None -> ("", "") | Some(x) -> x)
      | "validity_not_after" -> (match validity_not_after with | None -> ("", "") | Some(x) -> x)
      | "subject" -> (match subject with | None -> ("", "") | Some(x) -> x)
      | "subject_public_key_info" -> (match subject_public_key_info with | None -> ("", "") | Some(x) -> x)
      | "signature_algorithm" -> (match signature_algorithm with | None -> ("", "") | Some(x) -> x)
      | "signature_params" -> (match signature_params with | None -> ("", "") | Some(x) -> x)
      | "signature" -> (match signature with | None -> ("", "") | Some(x) -> x)
      | "tbs" -> (match tbs with | None -> ("", "") | Some(x) -> x)
      | _ -> let s = Printf.sprintf "x509 class get field: field %s is unknown" field in failwith s
    method set field a = match field with
      | "version" -> version <- Some(a)
      | "serial_number" -> serial_number <- Some(a)
      | "issuer" -> issuer <- Some(a)
      | "validity_not_before" -> validity_not_before <- Some(a)
      | "validity_not_after" -> validity_not_after <- Some(a)
      | "subject" -> subject <- Some(a)
      | "subject_public_key_info" -> subject_public_key_info <- Some(a)
      | "signature_algorithm" -> signature_algorithm <- Some(a)
      | "signature_params" -> signature_params <- Some(a)
      | "signature" -> signature <- Some(a)
      | "tbs" -> tbs <- Some(a)
      | _ -> let s = Printf.sprintf "x509 class set field: field %s is unknown" field in failwith s
    method print = 
      Printf.printf "Version    : 0x%s\n" (Helpers.sprint_hex_string (fst (s#get "version")));
      Printf.printf "SN         : 0x%s\n" (Helpers.sprint_hex_string (fst (s#get "serial_number")));
      Printf.printf "Issuer     : %s\n" (fst (s#get "issuer"));
      Printf.printf "Validity   : Not before: %s\n" (fst (s#get "validity_not_before"));
      Printf.printf "             Not after : %s\n" (fst (s#get "validity_not_after"));
      Printf.printf "Subject    : %s\n" (fst (s#get "subject"));
      Printf.printf "Signature  : Algorithm: %s\n" (fst (s#get "signature_algorithm"));
      Printf.printf "             Signature: %s\n" (Helpers.sprint_hex_string (fst (s#get "signature")));
      ()
  end

let x509_explore_node_position_with_oids x509_tree node_pos =
  let i = ref 0 in
  let the_end = ref false in
  let output = ref "" in
  while !the_end = false do
    let new_explore_pos = List.concat [node_pos; [ !i; 0; 0 ]] in
    let the_oid = (try (snd (Asn1.get_field_of_asn1_representation_from_node_pos x509_tree new_explore_pos)) with
      _ -> the_end := true; ("")) in
    let new_explore_pos = List.concat [node_pos; [ !i; 0; 1 ]] in
    let the_value = (try (snd (Asn1.get_field_of_asn1_representation_from_node_pos x509_tree new_explore_pos)) with
      _ -> the_end := true; ("")) in
    if !the_end = false then
      let the_type = Oids.get_name_from_oid (Asn1.get_oid_from_string 0 false Asn1.OID the_oid) Oids.oids in
      output := !output ^ (if !i = 0 then (Printf.sprintf "%s=%s" the_type the_value) else (Printf.sprintf ", %s=%s" the_type the_value));
      i := !i + 1
    else
      ()
  done;
  (!output)

let x509class_from_x509tree x509_tree =
  let x509 = new x509_cert in
  (* Get information from the tree *)
  let (version_der, version) = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 0; 0] in
  x509#set "version" (version, version_der);
  let (serial_number_der, serial_number) = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 1] in
  x509#set "serial_number" (serial_number, serial_number_der);
  x509#set "issuer" (x509_explore_node_position_with_oids x509_tree [0; 3], fst (Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 3]));
  let (validity_not_before_der, validity_not_before)  = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 4; 0] in
  let (validity_not_after_der, validity_not_after) = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 4; 1] in
  x509#set "validity_not_before" (validity_not_before, validity_not_before_der);
  x509#set "validity_not_after" (validity_not_after, validity_not_after_der);
  x509#set "subject" (x509_explore_node_position_with_oids x509_tree [0; 5], fst (Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [0; 5]));
  let (signature_algorithm_der, signature_algorithm)  = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [ 1; 0 ] in
  x509#set "signature_algorithm" (Oids.get_name_from_oid (Asn1.get_oid_from_string 0 false Asn1.OID signature_algorithm) Oids.oids, signature_algorithm_der);
  let (signature_der, signature)  = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [ 2 ] in
  x509#set "signature" (Asn1.get_bitstring_from_string 0 false Asn1.Bitstring signature, signature_der);
  let (tbs_der, tbs)  = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [ 0 ] in
  x509#set "tbs" (tbs_der, tbs_der);
  let (subject_public_key_info_der, subject_public_key_info) = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [1] in
  x509#set "subject_public_key_info" (subject_public_key_info_der, subject_public_key_info);
  (* Get the oid of the key type *)
  (* let key_type = Asn1.get_field_of_asn1_representation_from_node_pos x509_tree [1; 1; 1]; *)
  (x509)

let get_x509tree_from_der in_der = 
 (* First, we decode *)
  let decoded_asn1 = (try Asn1.decode_ber 0 in_der false false
    with _ -> raise(X509_ASN1_parse_error "Error when doing ASN1 decode for x509")) in
  let (check_x509, x509) = Asn1.check_asn1_scheme decoded_asn1 x509_certificate_asn1_scheme in
  if check_x509 = true then
    (x509)
  else
    raise(X509_ASN1_parse_error "Error when getting x509 scheme from ASN1")

let print_x509tree_from_der in_der = 
(* First, we decode *)
  let decoded_asn1 = (try Asn1.decode_ber 0 in_der false false
    with _ -> raise(X509_ASN1_parse_error "Error when doing ASN1 decode for x509")) in
  let (check_x509, x509) = Asn1.check_asn1_scheme decoded_asn1 x509_certificate_asn1_scheme in
  if check_x509 = true then
    Asn1.print_checked_asn1_scheme x509
  else
    raise(X509_ASN1_parse_error "Error when getting x509 scheme from ASN1")
