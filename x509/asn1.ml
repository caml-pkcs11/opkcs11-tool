(* ASN.1 handling *)
(* WARNING: this is a beta version    *)
(* Improvement and fixes are expected *)

IFDEF OCAML_NO_BYTES_MODULE THEN
module Bytes = String
ENDIF

(* Exceptions *)
exception ASN1_Bad_tag_num of int
exception ASN1_Bad_tag_class of int
exception ASN1_Bad_tag_pc of int
exception ASN1_Parse_error of string
exception ASN1_Bad_OID_decoding
exception ASN1_Bad_time_decoding
exception ASN1_Internal_Error of string
exception ASN1_Helper_Error of string

exception ASN1_Bad_string_to_int_conversion
exception ASN1_Integer_overflow
exception ASN1_Not_found
exception ASN1_Out_of_loop

exception ASN1_Check_Scheme_Error of string

exception ASN1_Construct_Error of string

type time = {year : int; month : int; day : int; hours : int; minutes : int; seconds : float; universal : bool; relative_to_utc : int option}

and asn1_tag = 
  | Boolean
  | Integer
  | Enumerated
  | Real
  | Bitstring
  | Octetstring
  | Null
  | Sequence
  | Set
  | OID
  | RelativeOID
  | ObjectDescriptor
  | External
  | Embedded_PDV
  | NumericString
  | PrintableString
  | TeletexString
  | VideotexString
  | VisibleString
  | IA5String
  | GraphicString
  | GeneralString
  | UniversalString
  | BMPString
  | UTF8String
  | CharString
  | UTCTime
  | GeneralizedTime
  | SpecificTag

and asn1_tag_type = 
  | Primitive | Constructed | Primitive_Constructed

and asn1_tag_class = 
  | Universal | Application | Context | Private

and asn1_info = asn1_tag * string * asn1_tag_type * asn1_tag_class * int

and asn1_value_fields =
  (* Position in the file *)
  | Pos | ASN1_Raw | ASN1_Content | ASN1_Info | ASN1_Constructed_Value_List | ASN1_Interpreted_Value

and asn1_interpreted_value = 
  | Boolean_value of bool
  | Real_value of string
  | OID_value of int array
  | Time_value of time
  | Printable_value of string
  | Rawstring_value of string
  | Null_value

and asn1_value =
  (* Offset in file * asn1_string * content_string * tag_info * content if contructed * real content * boolean telling if it has been modified *)
  | Boolean_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Integer_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Enumerated_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Real_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Null_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | OID_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | RelativeOID_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  (* Possibly constructed types *)
  | Sequence_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Set_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Bitstring_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool 
  | Octetstring_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | ObjectDescriptor_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | External_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | Embedded_PDV_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | NumericString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | PrintableString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | TeletexString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | VideotexString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | VisibleString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | IA5String_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | GraphicString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | GeneralString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | UniversalString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | BMPString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | UTF8String_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | CharString_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | UTCTime_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | GeneralizedTime_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool
  | SpecificTag_V of int * string * string * asn1_info * asn1_value list option * asn1_interpreted_value option * bool

and asn1_tag_explicit_implicit =
  | Implicit | Explicit

and asn1_simplified_representation =
  | Boolean_R of string 
  | Integer_R of string
  | Enumerated_R of string
  | Real_R of string
  | Null_R of string
  | OID_R of string * int array list
  | RelativeOID_R of string * int array list
  (* Possibly constructed types *)
  | Sequence_R of string * int * int * asn1_simplified_representation list
  | Set_R of string * int * int * asn1_simplified_representation list
  | Bitstring_R of string * asn1_simplified_representation list
  | Octetstring_R of string * asn1_simplified_representation list
  | ObjectDescriptor_R of string * asn1_simplified_representation list
  | External_R of string * asn1_simplified_representation list
  | Embedded_PDV_R of string * asn1_simplified_representation list
  | NumericString_R of string * asn1_simplified_representation list
  | PrintableString_R of string * asn1_simplified_representation list
  | TeletexString_R of string * asn1_simplified_representation list
  | VideotexString_R of string * asn1_simplified_representation list
  | VisibleString_R of string * asn1_simplified_representation list
  | IA5String_R of string * asn1_simplified_representation list
  | GraphicString_R of string * asn1_simplified_representation list
  | GeneralString_R of string * asn1_simplified_representation list
  | UniversalString_R of string * asn1_simplified_representation list
  | BMPString_R of string * asn1_simplified_representation list
  | UTF8String_R of string * asn1_simplified_representation list
  | CharString_R of string * asn1_simplified_representation list
  | UTCTime_R of string * asn1_simplified_representation list
  | GeneralizedTime_R of string * asn1_simplified_representation list
  | SpecificTag_R of string * int * asn1_tag_type * asn1_tag_explicit_implicit * asn1_simplified_representation list
  (* Special type 'option' to handle *)
  | Option_R of string * asn1_simplified_representation list
  | None_R
  | Any_R of string

let get_tag_from_asn1_simplified_representation asn1_r = 
  match asn1_r with
    Boolean_R(field_name) -> (field_name, Some Boolean, [])
  | Integer_R(field_name) -> (field_name, Some Integer, [])
  | Enumerated_R(field_name) -> (field_name, Some Enumerated, [])
  | Real_R(field_name) -> (field_name, Some Real, [])
  | Null_R(field_name) -> (field_name, Some Null, [])
  | OID_R(field_name, x) -> (field_name, Some OID, [])
  | RelativeOID_R(field_name, x) -> (field_name, Some RelativeOID, [])
  (* Possibly constructed types *)
  | Sequence_R(field_name, i, j, x) -> (field_name, Some Sequence, x)
  | Set_R(field_name, i, j, x) -> (field_name, Some  Set, x)
  | Bitstring_R(field_name, x) -> (field_name, Some  Bitstring, x)
  | Octetstring_R(field_name, x) -> (field_name, Some  Octetstring, x)
  | ObjectDescriptor_R(field_name, x) -> (field_name, Some  ObjectDescriptor, x)
  | External_R(field_name, x) -> (field_name, Some  External, x)
  | Embedded_PDV_R(field_name, x) -> (field_name, Some  Embedded_PDV, x)
  | NumericString_R(field_name, x) -> (field_name, Some  NumericString, x)
  | PrintableString_R(field_name, x) -> (field_name, Some  PrintableString, x)
  | TeletexString_R(field_name, x) -> (field_name, Some  TeletexString, x)
  | VideotexString_R(field_name, x) -> (field_name, Some  VideotexString, x)
  | VisibleString_R(field_name, x) -> (field_name, Some  VisibleString, x)
  | IA5String_R(field_name, x) -> (field_name, Some  IA5String, x)
  | GraphicString_R(field_name, x) -> (field_name, Some  GraphicString, x)
  | GeneralString_R(field_name, x) -> (field_name, Some  GeneralString, x)
  | UniversalString_R(field_name, x) -> (field_name, Some  UniversalString, x)
  | BMPString_R(field_name, x) -> (field_name, Some  BMPString, x)
  | UTF8String_R(field_name, x) -> (field_name, Some  UTF8String, x)
  | CharString_R(field_name, x) -> (field_name, Some  CharString, x)
  | UTCTime_R(field_name, x) -> (field_name, Some  UTCTime, x)
  | GeneralizedTime_R(field_name, x) -> (field_name, Some  GeneralizedTime, x)
  | SpecificTag_R(field_name, i, a, b, x) -> (field_name, Some  SpecificTag, x)
  (* Specific costructions for options and variable length sequences *)
  | Option_R(field_name, x) -> (field_name, None, x)
  | None_R -> ("", None, []) 
  | Any_R(field_name) -> (field_name, None, [])

let get_minmax_from_asn1_simplified_representation asn1_r = 
  match asn1_r with
    Sequence_R(_, i, j, _) -> (i,j)
  | Set_R(_, i, j, _) -> (i, j)
  | _ -> (0, 0)

let get_oids_from_asn1_simplified_representation asn1_r = 
  match asn1_r with
     OID_R(_, x) -> x
   | RelativeOID_R(_, x) -> x
   | _ -> []


let asn1_info_from_type the_type = 
  match the_type with
      Boolean -> (Boolean, "Boolean", Primitive, Universal, 0x1)
    | Integer -> (Integer, "Integer", Primitive, Universal, 0x2)
    | Enumerated -> (Enumerated, "Enumerated", Primitive, Universal, 0xa)
    | Real -> (Real, "Real", Primitive, Universal, 0x9)
    | Bitstring -> (Bitstring, "Bitstring", Primitive_Constructed, Universal, 0x3)
    | Octetstring -> (Octetstring, "Octetstring", Primitive_Constructed, Universal, 0x4)
    | Null -> (Null, "Null", Primitive, Universal, 0x5)
    | Sequence -> (Sequence, "Sequence", Constructed, Universal, 0x10)
    | Set -> (Set, "Set", Constructed, Universal, 0x11)
    | OID -> (OID, "OID", Primitive, Universal, 0x6)
    | RelativeOID -> (RelativeOID, "RelativeOID", Primitive, Universal, 0xd)
    | ObjectDescriptor -> (ObjectDescriptor, "ObjectDescriptor", Primitive_Constructed, Universal, 0x7)
    | External -> (External, "External", Constructed, Universal, 0x8)
    | Embedded_PDV -> (Embedded_PDV, "Embedded_PDV", Constructed, Universal, 0xb)
    | NumericString -> (NumericString, "NumericString", Primitive_Constructed, Universal, 0x12)
    | PrintableString -> (PrintableString, "PrintableString", Primitive_Constructed, Universal, 0x13)
    | TeletexString -> (TeletexString, "TeletexString", Primitive_Constructed, Universal, 0x14)
    | VideotexString -> (VideotexString, "VideotexString", Primitive_Constructed, Universal, 0x15)
    | VisibleString -> (VisibleString, "VisibleString", Primitive_Constructed, Universal, 0x1a)
    | IA5String -> (IA5String, "IA5String", Primitive_Constructed, Universal, 0x16)
    | GraphicString -> (GraphicString, "GraphicString", Primitive_Constructed, Universal, 0x19)
    | GeneralString -> (GeneralString, "GeneralString", Primitive_Constructed, Universal, 0x1b)
    | UniversalString -> (UniversalString, "UniversalString", Primitive_Constructed, Universal, 0x1c)
    | BMPString -> (BMPString, "BMPString", Primitive_Constructed, Universal, 0x1e)
    | UTF8String -> (UTF8String, "UTF8String", Primitive_Constructed, Universal, 0xc)
    | CharString -> (CharString, "CharString", Primitive_Constructed, Universal, 0x1d )
    | UTCTime -> (UTCTime, "UTCTime", Primitive_Constructed, Universal, 0x17)
    | GeneralizedTime -> (GeneralizedTime, "GeneralizedTime", Primitive_Constructed, Universal, 0x18)
    | SpecificTag -> (SpecificTag, "SpecificTag", Primitive_Constructed, Context, 0x0)

let asn1_info_from_tag_id tag = 
  match tag with
      0x1  -> (Boolean, "Boolean", Primitive, Universal, 0x1)
    | 0x2  -> (Integer, "Integer", Primitive, Universal, 0x2)
    | 0xa  -> (Enumerated, "Enumerated", Primitive, Universal, 0xa)
    | 0x9  -> (Real, "Real", Primitive, Universal, 0x9)
    | 0x3  -> (Bitstring, "Bitstring", Primitive_Constructed, Universal, 0x3)
    | 0x4  -> (Octetstring, "Octetstring", Primitive_Constructed, Universal, 0x4)
    | 0x5  -> (Null, "Null", Primitive, Universal, 0x5)
    | 0x10 -> (Sequence, "Sequence", Constructed, Universal, 0x10)
    | 0x11 -> (Set, "Set", Constructed, Universal, 0x11)
    | 0x6  -> (OID, "OID", Primitive, Universal, 0x6)
    | 0xd  -> (RelativeOID, "RelativeOID", Primitive, Universal, 0xd)
    | 0x7  -> (ObjectDescriptor, "ObjectDescriptor", Primitive_Constructed, Universal, 0x7)
    | 0x8  -> (External, "External", Constructed, Universal, 0x8)
    | 0xb  -> (Embedded_PDV, "Embedded_PDV", Constructed, Universal, 0xb)
    | 0x12 -> (NumericString, "NumericString", Primitive_Constructed, Universal, 0x12)
    | 0x13 -> (PrintableString, "PrintableString", Primitive_Constructed, Universal, 0x13)
    | 0x14 -> (TeletexString, "TeletexString", Primitive_Constructed, Universal, 0x14)
    | 0x15 -> (VideotexString, "VideotexString", Primitive_Constructed, Universal, 0x15)
    | 0x1a -> (VisibleString, "VisibleString", Primitive_Constructed, Universal, 0x1a)
    | 0x16 -> (IA5String, "IA5String", Primitive_Constructed, Universal, 0x16)
    | 0x19 -> (GraphicString, "GraphicString", Primitive_Constructed, Universal, 0x19)
    | 0x1b -> (GeneralString, "GeneralString", Primitive_Constructed, Universal, 0x1b)
    | 0x1c -> (UniversalString, "UniversalString", Primitive_Constructed, Universal, 0x1c)
    | 0x1e -> (BMPString, "BMPString", Primitive_Constructed, Universal, 0x1e)
    | 0xc  -> (UTF8String, "UTF8String", Primitive_Constructed, Universal, 0xc)
    | 0x1d -> (CharString, "CharString", Primitive_Constructed, Universal, 0x1d )
    | 0x17 -> (UTCTime, "UTCTime", Primitive_Constructed, Universal, 0x17)
    | 0x18 -> (GeneralizedTime, "GeneralizedTime", Primitive_Constructed, Universal, 0x18)
    | _    -> raise ASN1_Not_found

let asn1_class_from_int c = 
  match c with
      0x0 -> Universal
    | 0x1 -> Application
    | 0x2 -> Context
    | 0x3 -> Private
    | _ -> raise(ASN1_Bad_tag_class c)

let asn1_int_from_class c = 
  match c with
      Universal -> 0x0
    | Application -> 0x1
    | Context -> 0x2
    | Private -> 0x3

let asn1_pc_from_int pc = 
  match pc with 
      0X0 -> Primitive
    | 0x1 -> Constructed
    | _ -> raise(ASN1_Bad_tag_pc pc)

let asn1_int_from_pc pc = 
  match pc with 
      Primitive -> 0x0
    | Constructed -> 0x1
    | _ -> raise(ASN1_Bad_tag_pc 0x2)

let get_common_fields_from_asn1_value value =
  match value with
  | Boolean_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Integer_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Enumerated_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Real_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Bitstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Octetstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Null_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Sequence_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Set_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | OID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | RelativeOID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | External_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | Embedded_PDV_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | NumericString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | PrintableString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | TeletexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | VideotexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | VisibleString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | IA5String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | GraphicString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | GeneralString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | UniversalString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | BMPString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | UTF8String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | CharString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | UTCTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | GeneralizedTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)
  | SpecificTag_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> (pos, asn1_string, content_string, tag_info, constructed_content, is_modified)

let get_real_type_from_asn1_value value = 
   match value with
  | Boolean_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Integer_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Enumerated_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Real_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Bitstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Octetstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Null_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Sequence_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Set_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | OID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | RelativeOID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | External_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | Embedded_PDV_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | NumericString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | PrintableString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | TeletexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | VideotexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | VisibleString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | IA5String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | GraphicString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | GeneralString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | UniversalString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | BMPString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | UTF8String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | CharString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | UTCTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | GeneralizedTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
  | SpecificTag_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, _) -> real_type
 

let get_tag_info_from_identifier_octets id_octets_byte = 
  let id_octets = Char.code id_octets_byte in
  let pc = ((id_octets lsr 5) land 0x1) in
  let tag_class = (id_octets lsr 6) in
  if compare (asn1_class_from_int tag_class) Universal <> 0 then
    (* We do not have a native ASN1 type, return it 'as is' with its full tag *)
    (SpecificTag, "SpecificTag", (asn1_pc_from_int pc), (asn1_class_from_int tag_class), id_octets land 0x1f)
  else
    (* Extract tag *)
    let tag = (id_octets land 0x1f) in
    let (tag_type, string_info, possible_pc, possible_class, _)  = (try asn1_info_from_tag_id tag with
      ASN1_Not_found -> raise(ASN1_Bad_tag_num tag)) in
    if (compare (asn1_pc_from_int pc) Primitive = 0) && 
       ((compare possible_pc Primitive = 0) || (compare possible_pc Primitive_Constructed) = 0) then
         (tag_type, string_info, (asn1_pc_from_int pc), (asn1_class_from_int tag_class), tag)
    else
      if (compare (asn1_pc_from_int pc) Constructed = 0) && 
         ((compare possible_pc Constructed = 0) || (compare possible_pc Primitive_Constructed) = 0) then
         (tag_type, string_info, (asn1_pc_from_int pc), (asn1_class_from_int tag_class), tag)
      else
        raise(ASN1_Bad_tag_pc pc)

(* Get tag info from a string *)
let get_tag_info_from_string in_string =
  if String.length in_string > 0 then
    (get_tag_info_from_identifier_octets in_string.[0])
  else
    raise(ASN1_Parse_error "String too short: no ASN1 tag")

(* Get total length of the object *)
let int_of_big_endian_string in_string = 
  if String.length in_string > 4 then
    raise ASN1_Integer_overflow
  else
    if String.length in_string = 0 then
      (0)
    else
      let out_int = ref 0 in
      for i = 0 to (String.length in_string)-1 do
        out_int := !out_int lxor ((Char.code in_string.[(String.length in_string)-1-i]) lsl (8*i));
      done;
      (!out_int)

let get_asn1_content_from_string in_string =
  let first_byte = (Char.code in_string.[1]) in
  (* Do we have the long or short form? *)
  if (first_byte lsr 7) = 0x1 then
    (* This is the long form *)
    (* If yes, get the number of bytes encoding the length *)
    let num_bytes = (first_byte land 0x7f) in
    (* Do we have a form with an EOC? *)
    if num_bytes = 0 then
      (* Check that the type is constructed, or return an error *)
      let pc = ((Char.code in_string.[0]) lsr 5) land 0x1 in
      if pc = 1 then
        (0, String.sub in_string 2 (String.length in_string - 2))
      else
        raise(ASN1_Parse_error "Got an ASN1 length of 0 for non constructed type") 
    else
      if (String.length in_string) < num_bytes + 2 then
        raise(ASN1_Parse_error "String too short during ASN1 length extraction")
      else
        let length = (try int_of_big_endian_string (String.sub in_string 2 num_bytes) with 
          _ -> raise(ASN1_Parse_error "String too short during ASN1 length extraction")) in
        let asn1_content = (try String.sub in_string (2+num_bytes) length with
          _ -> raise(ASN1_Parse_error "String too short during ANS1 content extraction")) in
        (num_bytes + 2 + (String.length asn1_content), asn1_content)
  else
    (* This is the short form, only one byte encoding the length *)
    let length = (try int_of_big_endian_string (String.sub in_string 1 1) with 
      _ -> raise(ASN1_Parse_error "String too short during ANS1 content extraction")) in
    let asn1_content = (try String.sub in_string 2 length with
      _ -> raise(ASN1_Parse_error "String too short during ANS1 content extraction")) in
    (2 + (String.length asn1_content), asn1_content)

(********** Primitive types decoders ********************)
(* Helpers for interpreted primitive types *)
let get_boolean_from_string pos verbosity tag_type asn1_content = 
  if asn1_content.[0] = (Char.chr 0) then
    false
  else
    true
let get_real_from_string pos verbosity tag_type asn1_content = 
  (* FIXME: for now a real is only its bare string    *)
  (* We would want to have a better interpretation of *)
  (* this bare value for arbitrary precision ...      *)
  (asn1_content)

(* Generic power function to compute power of 128 *)
(* (useful for OID computing)                     *)
(* (or time computing)                            *)
let pow one mul a n =
  let rec g p x = function
  | 0 -> x
  | i ->
      g (mul p p) (if i mod 2 = 1 then mul p x else x) (i/2)
  in
  g a one n

(* Converts an ASCII string with numbers to *)
(* an integer                               *)
let string_to_decimal in_string = 
  let int_value = ref 0 in
  if (String.length in_string) = 0 then
    (0)
  else
    begin
    for i=0 to (String.length in_string)-1 do
      if ((Char.code in_string.[i]) < 0x30) || ((Char.code in_string.[i]) > 0x39) then
        raise(ASN1_Bad_string_to_int_conversion)
      else
        int_value := !int_value + ((pow 1 ( * ) 10 ((String.length in_string)-1-i)) * ((Char.code in_string.[i]) - 0x30));
    done;
    (!int_value)
    end

let get_time_from_string pos verbosity tag_type asn1_content = 
  match tag_type with
    UTCTime -> 
      if (String.length asn1_content < 12) then
        raise(ASN1_Bad_time_decoding)
      else
        let year = string_to_decimal (String.sub asn1_content 0 2) in
        let month = string_to_decimal (String.sub asn1_content 2 2) in
        let day = string_to_decimal (String.sub asn1_content 4 2) in
        let hours = string_to_decimal (String.sub asn1_content 6 2) in
        let minutes = string_to_decimal (String.sub asn1_content 8 2) in
        let seconds = string_to_decimal (String.sub asn1_content 10 2) in
        let universal = (
          if (String.length asn1_content) > 12 then
            if (String.length asn1_content) <> 13 then
              raise(ASN1_Bad_time_decoding)
            else if (asn1_content.[12] = 'Z') then
              true
            else          
              raise(ASN1_Bad_time_decoding)
          else
            false
        ) in
        ({ year=(year+2000); month=month; day=day; hours=hours; minutes=minutes; seconds=float_of_int seconds; universal=universal; relative_to_utc=None })
   | GeneralizedTime -> 
      if (String.length asn1_content < 14) then
        raise(ASN1_Bad_time_decoding)
      else
        (* FIXME: implement the relative and floating point part *)
        let year = string_to_decimal (String.sub asn1_content 0 4) in
        let month = string_to_decimal (String.sub asn1_content 2 2) in
        let day = string_to_decimal (String.sub asn1_content 4 2) in
        let hours = string_to_decimal (String.sub asn1_content 6 2) in
        let minutes = string_to_decimal (String.sub asn1_content 8 2) in
        let seconds = string_to_decimal (String.sub asn1_content 10 2) in
        (* Trailing Z? *)
        let universal = (
          if (String.length asn1_content) > 14 then
            if (asn1_content.[String.length asn1_content-1] = 'Z') then
              false
            else
              true
          else
            true
        ) in
        ({ year=year; month=month; day=day; hours=hours; minutes=minutes; seconds=float_of_int seconds; universal=universal; relative_to_utc= Some 0})
   | _ -> raise(ASN1_Bad_time_decoding)

let get_oid_from_string pos verbosity tag_type asn1_content =
  let oids = ref [| |] in
  if (String.length asn1_content) > 0 then
  (* First two values in one octet *)
    let num1 = (Char.code asn1_content.[0])/40 in
    let num2 = (Char.code asn1_content.[0]) mod 40 in
    oids := Array.concat [ !oids; [| num1; num2 |] ];
    (* Parse the rest *)
    let other_nums_string = String.sub asn1_content 1 ((String.length asn1_content)-1) in
    (* Grab the oid through the encoding of the most significant bit of each byte *)
    let curr_nums_array = ref [||]  in
    for i=0 to (String.length other_nums_string)-1 do
      let byte = other_nums_string.[i] in
      curr_nums_array := Array.concat [ !curr_nums_array; [| (Char.code byte) land 0x7f |] ];
      if ((Char.code byte) land 0x80) = 0 then
        (* We have reached the end of a number *)
        (* Compute the num using the 128 base  *)
        let num_to_store = ref 0 in
        Array.iteri (fun i x -> num_to_store := !num_to_store + ((pow 1 ( * ) 128 (Array.length !curr_nums_array-1-i)) * x);) !curr_nums_array;
        oids := Array.concat [ !oids; [| !num_to_store |] ];
        curr_nums_array := [||];
    done;
    (!oids)
  else
    (* Empty oids FIXME: is it standard or should we return an error? *)
    (!oids)

let get_string_from_encoded_string pos verbosity tag_type asn1_content =
  (* FIXME: add sanity checks and raise a warning *)
  match tag_type with
  (* Printable, IA5String ans UTF8String are printable as is *)
    PrintableString -> (asn1_content)
  | IA5String -> (asn1_content)
  | UTF8String -> (asn1_content)
  (* Obsolete encodings *)
  | _ -> 
    let _ = (if verbosity = true then Printf.printf "WARNING: detected obsolete string encoding at position %d\n" pos else ()) in
      (asn1_content)

IFDEF OCAML_NO_BYTES_MODULE THEN
let get_bitstring_from_string pos verbosity tag_type asn1_content =
  match tag_type with
    | Bitstring ->
      if (String.length asn1_content) < 2 then
        failwith "Bitstring to string conversion: string length must be > 1"
      else
        (* Get the bit mask of the last byte *)
        let mask_low = (Char.code asn1_content.[0])  in
        let mask_high = (lnot mask_low) land 0xff in
        if mask_high = 0xff then
          (* We keep all the bits of the last byte *)
          (String.sub asn1_content 1 (String.length asn1_content - 1))
        else
          (* We keep a strict subset of the last byte *)
          (* Shift right the string with the appropriate amount of bits *)
          let numbits = Helpers.find_bits_number (String.make 1 (Char.chr mask_low)) in
          let output = String.make (String.length asn1_content - 1) (Char.chr 0x0) in
          let old_byte = ref 0x0 in
          for i = 1 to (String.length asn1_content - 1) do
            String.set output i (Char.chr (((Char.code asn1_content.[i]) lsr numbits) lxor !old_byte));
            old_byte := (((Char.code asn1_content.[i]) land mask_high) lsl (7-numbits)) land 0xff;
          done;
          (output)
    | _ -> failwith "Bitstring to string conversion: bad tag type"
ENDIF

IFNDEF OCAML_NO_BYTES_MODULE THEN
let get_bitstring_from_string pos verbosity tag_type asn1_content =
  match tag_type with
    | Bitstring ->
      if (String.length asn1_content) < 2 then
        failwith "Bitstring to string conversion: string length must be > 1"
      else
        (* Get the bit mask of the last byte *)
        let mask_low = (Char.code asn1_content.[0])  in
        let mask_high = (lnot mask_low) land 0xff in
        if mask_high = 0xff then
          (* We keep all the bits of the last byte *)
          (String.sub asn1_content 1 (String.length asn1_content - 1))
        else
          (* We keep a strict subset of the last byte *)
          (* Shift right the string with the appropriate amount of bits *)
          let numbits = Helpers.find_bits_number (String.make 1 (Char.chr mask_low)) in
          let output = Bytes.make (String.length asn1_content - 1) (Char.chr 0x0) in
          let old_byte = ref 0x0 in
          for i = 1 to (String.length asn1_content - 1) do
            Bytes.set output i (Char.chr (((Char.code asn1_content.[i]) lsr numbits) lxor !old_byte));
            old_byte := (((Char.code asn1_content.[i]) land mask_high) lsl (7-numbits)) land 0xff;
          done;
          (Bytes.to_string output)
    | _ -> failwith "Bitstring to string conversion: bad tag type"
ENDIF

let get_octetstring_from_string pos verbosity tag_type asn1_content =
  match tag_type with
    | Octetstring ->
      (* Raw content for octet string *) 
      (asn1_content)
    | _ -> failwith "Octetstring to string conversion: bad tag type"


(* Handle decoding types *)
let rec decode_ber pos in_string deep_search verbose = 
  let (tag_type, string_info, pc, tag_class, tag_num) = (try get_tag_info_from_string in_string with
    _ -> raise(ASN1_Parse_error "Error during BER decoding for tag")) in
  let (used_length, asn1_content) = (try get_asn1_content_from_string in_string  with
    _ -> raise(ASN1_Parse_error "Error during BER decoding for ASN1 length and content")) in
  if (used_length = 0) && (verbose = true) then
    (* We have an EOC *)
    Printf.printf "WARNING: non canonical encoding (with EOC) detected at position %d\n" pos;
  let asn1_info = (tag_type, string_info, pc, tag_class, tag_num) in
  let returned_value_list = ref None in
  let interpreted_value = ref None in
  (* We need to keep track of the real used length *)
  let real_used_length = ref used_length in
  let _ = (
    match pc with
    (* Primitive types are the end of the parsing recursion *)
      Primitive -> 
        (* For primitive types, interpret the value depending on the type *)
        (match tag_type with
          Boolean ->  interpreted_value := Some (Boolean_value(get_boolean_from_string pos verbose tag_type asn1_content))
        | Real -> interpreted_value := Some (Real_value(get_real_from_string pos verbose tag_type asn1_content))
        | (UTCTime | GeneralizedTime) -> interpreted_value := Some (Time_value(get_time_from_string pos verbose tag_type asn1_content))
        | (OID | RelativeOID) -> interpreted_value := Some (OID_value(get_oid_from_string pos verbose tag_type asn1_content))
        (* For strings, decode the given string depending on the encoding *)
        | (PrintableString | IA5String | UTF8String | TeletexString | VideotexString | GeneralString | GraphicString) -> interpreted_value := Some (Printable_value(get_string_from_encoded_string pos verbose tag_type asn1_content))
        (* Else we put the string *)
        | _ -> 
          interpreted_value := Some (Rawstring_value(asn1_content));
          (* If we have an octet string or a bit string, these could encapsulate other values *)
          if deep_search = false then
              match tag_type with
                Octetstring -> 
                begin
                (* Octetstring: check the bare content *)
                try (let decoded_encapsulated_asn1 = decode_ber (pos+(used_length - (String.length asn1_content))) asn1_content deep_search verbose in            
                (* Check if we have really decoded the whole content of the ASN.1 *)
                let (_, decoded_encapsulated_asn1_string, _, _, _, _) = get_common_fields_from_asn1_value decoded_encapsulated_asn1 in
                if (String.length decoded_encapsulated_asn1_string) = (String.length asn1_content) then
                  returned_value_list := Some [ decoded_encapsulated_asn1 ];) 
                with _ -> ()
                end
              | Bitstring -> 
                begin
                (* Bitstring: the first octet encodes the bit mask, it should be zero if the *)
                (* bitstring encapsulates something                                          *)
                if (String.length asn1_content) > 0 then
                  if (Char.code asn1_content.[0]) = 0 then
                    let sub_string = String.sub asn1_content 1 ((String.length asn1_content)-1) in
                    try (let decoded_encapsulated_asn1 = decode_ber (pos+(used_length - (String.length asn1_content))+1) sub_string deep_search verbose in
                    (* Check if we have really decoded the whole content of the ASN.1 *)
                    let (_, decoded_encapsulated_asn1_string, _, _, _, _) = get_common_fields_from_asn1_value decoded_encapsulated_asn1 in
                    if (String.length decoded_encapsulated_asn1_string) = (String.length sub_string) then
                      returned_value_list := Some [ decoded_encapsulated_asn1 ];)
                    with _ -> ()
                end
             | _ -> ()
          else
            (* If we are in "deep search mode", get the possible values inside the strings for any type *)
            (* Try to decode the substrings until we reach the end failing                              *)
            (* WARNING: this deep search is *not* sound                                                 *)
            try (for i = 0 to (String.length asn1_content)-1 do
              let sub_string = String.sub asn1_content i ((String.length asn1_content)-i) in
              try let decoded_encapsulated_asn1 = decode_ber (pos+(used_length - (String.length asn1_content))+i) sub_string true verbose in
                returned_value_list := Some [ decoded_encapsulated_asn1 ];
                raise ASN1_Out_of_loop;
              with   ASN1_Out_of_loop -> raise ASN1_Out_of_loop
                   | _ -> ()
            done;) with ASN1_Out_of_loop -> ();
        )
    (* Constructed types: recurse until we have nothing left to parse *)
    | Constructed -> (
      (* We have a constructed type for other than Sequence or Set, this is not canonical *)
      if (compare tag_type Sequence <> 0) && (compare tag_type Set <> 0) && (compare tag_type SpecificTag <> 0) && (verbose = true) then
         Printf.printf "WARNING: non canonical encoding (constructed type other than SEQUENCE, SET or SPECIFICTAG) detected at position %d\n" pos;
      (* Two cases: we have a constructed type with length, parse it iteratively *)
      (* We have a constructed type with a zero length, meaning that we are searching for an EOC to close the current object parsing *)
      let new_string_to_parse = ref asn1_content in
      let current_position = (
        if used_length <> 0 then 
          ref (pos + (used_length - (String.length asn1_content)))
        else 
          ref (pos + 2)) in 
      (* Recurse through all the elements of the sequence *)
      try (while (String.length !new_string_to_parse > 0) do
        (* Check for the EOC value *)
        let continue = (
          if used_length = 0 then
            let eoc = String.make 2 (Char.chr 0) in
            let test_eoc = (try String.sub !new_string_to_parse 0 2 
              with _ -> raise(ASN1_Parse_error "Error when getting EOC from ASN1 constructed type with length 0")) in
            if compare test_eoc eoc = 0 then
              (* Stop here *)
              (* Add the two EOC bytes plus two header bytes to the length *)
              let _ = (real_used_length := !real_used_length + 4) in
              (false)
            else
              (* Continue to grab *)
              (true)
          else
            (* Not and EOC type, continue *)
            (true)
        ) in
        if continue = true then
          let returned_value = decode_ber !current_position !new_string_to_parse deep_search verbose in
          let (_, new_asn1_string, new_asn1_content, info, _, _) = get_common_fields_from_asn1_value returned_value in
          let (new_tag_type, _, _, _, _) = info in
          (* For other than SEQUENCE, SET and SPECIFICTAG, we cannot encapsulate other types than the parent one *)
          if (compare tag_type Sequence <> 0) && (compare tag_type Set <> 0) && (compare tag_type SpecificTag <> 0) && (verbose = true) then
            if (compare new_tag_type tag_type <> 0) then
              Printf.printf "WARNING: non compliant encoding (type other than SEQUENCE, SET or SPECIFICTAG contains other types) detected at position %d\n" pos;
          new_string_to_parse := String.sub !new_string_to_parse (String.length new_asn1_string) ((String.length !new_string_to_parse) - (String.length new_asn1_string));
          current_position := !current_position + (String.length new_asn1_string);
          real_used_length := (
            if used_length = 0 then
              !real_used_length + (String.length new_asn1_string)
            else
              used_length);
          if !returned_value_list = None then
            returned_value_list := Some [ returned_value ]
          else
            returned_value_list := Some (List.append (Helpers.get !returned_value_list) [ returned_value ])
        else
          (* Stop the loop *)
          raise ASN1_Out_of_loop  
      done;) with ASN1_Out_of_loop -> ())
    | _ -> raise(ASN1_Parse_error "Unknown P/C type during BER decoding")) in
    (* If we had a special case with EOC types, take the real content (since we did not knew the real length till now) *)
    let asn1_content = (
      if used_length = 0 then
        (* Substring where we remove the EOC *)
        String.sub asn1_content 0 (!real_used_length-2)
      else
        asn1_content) in
    (* Match on tag type *)
    match tag_type with
   (* Primitive only types *)
     Boolean ->  Boolean_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   | Integer ->  Integer_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   | Enumerated ->  Enumerated_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   | Real ->  Real_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   | Null ->  Null_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, Some Null_value, false)
   | OID ->  OID_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   | RelativeOID ->  RelativeOID_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, None, !interpreted_value, false)
   (* Possibly constructed types *)
   | Bitstring ->  Bitstring_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | Octetstring ->  Octetstring_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | ObjectDescriptor ->  ObjectDescriptor_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | NumericString ->  NumericString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | PrintableString ->  PrintableString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | TeletexString ->  TeletexString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | VideotexString ->  VideotexString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | VisibleString ->  VisibleString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | IA5String ->  IA5String_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | GraphicString ->  GraphicString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | GeneralString ->  GeneralString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | UniversalString ->  UniversalString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | BMPString ->  BMPString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | UTF8String ->  UTF8String_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | CharString ->  CharString_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | UTCTime ->  UTCTime_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | GeneralizedTime ->  GeneralizedTime_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, !interpreted_value, false)
   | SpecificTag ->  SpecificTag_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, None, false)
   (* Constructed only types = no interpreted value *)
   | Sequence ->  Sequence_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, None, false)
   | Set ->  Set_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, None, false)
   | External ->  External_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, None, false)
   | Embedded_PDV ->  Embedded_PDV_V(pos, String.sub in_string 0 !real_used_length, asn1_content, asn1_info, !returned_value_list, None, false)

let rec print_asn1_tree level asn1_container = 
  (* Extract information *)
  let (pos, asn1_string, asn1_content, info, encapsulated_values, _) = get_common_fields_from_asn1_value asn1_container in
  let (tag_type, string_info, pc, tag_class, tag_num) = info in
  let spaces = ref "" in 
  for i = 1 to level do
    spaces := Printf.sprintf "%s  " !spaces;
  done;
  let specific_tag_index = (
   match tag_type with
      SpecificTag -> Printf.sprintf "[%d]" tag_num
    | _ -> "") in
  if encapsulated_values <> None then
    let is_prim_encapsulated = (if compare pc Primitive = 0 then "(encapsulates)" else "") in
    let _ = Printf.printf "--------\n" in
    let _ = Helpers.print_hex_array (Helpers.string_to_char_array  (String.sub asn1_string 0 ((String.length asn1_string) - (String.length asn1_content)))) in
    let _ = Printf.printf "%6d, %6d, %s%s%s %s {\n" pos (String.length asn1_content) !spaces string_info specific_tag_index is_prim_encapsulated in
    let _ = Helpers.print_hex_array (Helpers.string_to_char_array  (String.sub asn1_content 0 (min (String.length asn1_content) 8))) in
    (* Recurse through all the subvalues *)
    let _ = List.iter (print_asn1_tree (level + 1)) (Helpers.get encapsulated_values) in
    Printf.printf "                %s}\n" !spaces; 
  else
    (* OID *)
    let interpreted_value = (
      match asn1_container with
          OID_V(_, _, _, _, _, Some (OID_value(oid_array)), _) -> let s = ref "" in Array.iter (fun x -> s := Printf.sprintf "%s%d " !s x) oid_array; Printf.sprintf "{ %s}" !s
        | (UTCTime_V(_, _, _, _, _, Some (Time_value(time)), _) | GeneralizedTime_V(_, _, _, _, _, Some (Time_value(time)), _)) -> 
          let the_seconds = (
            if compare (ceil time.seconds) time.seconds = 0 then
              Printf.sprintf "%02d" (int_of_float time.seconds)
            else
              Printf.sprintf "%f" time.seconds             
          ) in
          let locality = if time.universal = true then "GMT" else "LOCAL" in
          let s = Printf.sprintf "%02d/%02d/%d %02d:%02d:%s, %s" time.day time.month time.year time.hours time.minutes the_seconds locality in s 
        | _ -> "") in
    let _ = Printf.printf "--------\n" in
    let _ = Helpers.print_hex_array (Helpers.string_to_char_array  (String.sub asn1_string 0 ((String.length asn1_string) - (String.length asn1_content)))) in
    let _ = Printf.printf "%6d, %6d, %s%s%s  Value=%s\n" pos (String.length asn1_content) !spaces string_info specific_tag_index interpreted_value in
    Helpers.print_hex_array (Helpers.string_to_char_array  (String.sub asn1_content 0 (min (String.length asn1_content) 8)));
  () 


(*******************************************************************)
(* Check if a given ASN.1 scheme corresponds to the representation *)
(* The nodes are then returned in a list of ASN1 values            *)
 
(* This function creates a new ASN1 container where an input container *)
(* is encapsulated inside a representation node also given as input    *)
let implicit_tag_new_asn1_container_from_representation representation_node encapsulated_values pos asn1_content =
  let interpreted_value = (
    match representation_node with
      (* For printable types, populate the real value since it should be *)
      | PrintableString_R(field_name, x) ->
          Some (Printable_value(get_string_from_encoded_string 0 false PrintableString asn1_content))
      | IA5String_R(field_name, x) ->
          Some (Printable_value(get_string_from_encoded_string 0 false IA5String asn1_content))
      | VideotexString_R(field_name, x) -> 
          Some (Printable_value(get_string_from_encoded_string 0 false VideotexString asn1_content))
      | UTF8String_R(field_name, x) -> 
          Some (Printable_value(get_string_from_encoded_string 0 false UTF8String asn1_content))
      | TeletexString_R(field_name, x) -> 
          Some (Printable_value(get_string_from_encoded_string 0 false TeletexString asn1_content))
      | GeneralString_R(field_name, x) -> 
          Some (Printable_value(get_string_from_encoded_string 0 false GeneralString asn1_content))
      | GraphicString_R(field_name, x) -> 
          Some (Printable_value(get_string_from_encoded_string 0 false GraphicString asn1_content))
      | _ -> None
  ) in
  match representation_node with
   (* Possibly constructed types *)
   (* For printable types, populate the real value since it should be *)
   | PrintableString_R(field_name, x) -> PrintableString_V(pos, "", "", asn1_info_from_type PrintableString, encapsulated_values, interpreted_value, false)
   | IA5String_R(field_name, x) -> IA5String_V(pos, "", "", asn1_info_from_type IA5String, encapsulated_values, interpreted_value, false)
   | VideotexString_R(field_name, x) -> VideotexString_V(pos, "", "", asn1_info_from_type VideotexString, encapsulated_values, interpreted_value, false)
   | UTF8String_R(field_name, x) -> UTF8String_V(pos, "", "", asn1_info_from_type UTF8String, encapsulated_values, interpreted_value, false)
   | TeletexString_R(field_name, x) -> TeletexString_V(pos, "", "", asn1_info_from_type TeletexString, encapsulated_values, interpreted_value, false)
   | GeneralString_R(field_name, x) -> GeneralString_V(pos, "", "", asn1_info_from_type GeneralString, encapsulated_values, interpreted_value, false)
   | GraphicString_R(field_name, x) -> GraphicString_V(pos, "", "", asn1_info_from_type GraphicString, encapsulated_values, interpreted_value, false)
   (********)
   | Bitstring_R(field_name, x) -> Bitstring_V(pos, "", "", asn1_info_from_type Bitstring, encapsulated_values, None, false)
   | Octetstring_R(field_name, x) -> Octetstring_V(pos, "", "", asn1_info_from_type Octetstring, encapsulated_values, None, false)
   | ObjectDescriptor_R(field_name, x) -> ObjectDescriptor_V(pos, "", "", asn1_info_from_type ObjectDescriptor, encapsulated_values, None, false)
   | NumericString_R(field_name, x) -> NumericString_V(pos, "", "", asn1_info_from_type NumericString, encapsulated_values, None, false)
   | VisibleString_R(field_name, x) -> VisibleString_V(pos, "", "", asn1_info_from_type VisibleString, encapsulated_values, None, false)
   | UniversalString_R(field_name, x) -> UniversalString_V(pos, "", "", asn1_info_from_type UniversalString, encapsulated_values, None, false)
   | BMPString_R(field_name, x) -> BMPString_V(pos, "", "", asn1_info_from_type BMPString, encapsulated_values, None, false)
   | CharString_R(field_name, x) -> CharString_V(pos, "", "", asn1_info_from_type CharString, encapsulated_values, None, false)
   | UTCTime_R(field_name, x) -> UTCTime_V(pos, "", "", asn1_info_from_type UTCTime, encapsulated_values, None, false)
   | GeneralizedTime_R(field_name, x) -> GeneralizedTime_V(pos, "", "", asn1_info_from_type GeneralizedTime, encapsulated_values, None, false)
   | SpecificTag_R(field_name, i, a, b, x) -> SpecificTag_V(pos, "", "", asn1_info_from_type SpecificTag, encapsulated_values, None, false)
   (* Constructed only types *)
   | Sequence_R(field_name, i, j, x) -> Sequence_V(pos, "", "", asn1_info_from_type Sequence, encapsulated_values, None, false)
   | Set_R(field_name, i, j, x) -> Set_V(pos, "", "", asn1_info_from_type Set, encapsulated_values, None, false)
   | External_R(field_name, x) -> External_V(pos, "", "", asn1_info_from_type External, encapsulated_values, None, false)
   | Embedded_PDV_R(field_name, x) -> Embedded_PDV_V(pos, "", "", asn1_info_from_type Embedded_PDV, encapsulated_values, None, false)
   (* The Option_R and None_R are not allowed when dealing with implicit specific tags *)
   | Option_R(field_name, x) -> raise(ASN1_Check_Scheme_Error "Internal error: Option_R found as an implicit SpecificTag_R, which is forbidden")
   | None_R -> raise(ASN1_Check_Scheme_Error "Internal error: None_R found as an implicit SpecificTag_R, which is forbidden")
   | Any_R(field_name) -> raise(ASN1_Not_found)
   | _ -> raise(ASN1_Check_Scheme_Error "Internal error: forbidden type found as an implicit SpecificTag_R (Boolean, Integer, Enumerated, Real, Null, OID)")

(* This function fuses two node lists of string * asn1_value with removing *)
(* a value if its position has already been explored                       *)
let fuse_nodes_lists node_list1 node_list2 = 
  let new_list = ref node_list1 in
  let _ = List.iter (
    fun (node_ref2, s2, n2) -> 
    let check_found = List.find_all (fun (node_ref1, s1, n1) ->
      let (pos1, _, _, _, _, _) = get_common_fields_from_asn1_value n1 in
      let (pos2, _, _, _, _, _) = get_common_fields_from_asn1_value n2 in
      if pos1 = pos2 then true else false
    ) node_list1 in
    if List.length check_found = 0 then
      new_list := List.append !new_list [(node_ref2, s2, n2)];
  ) node_list2 in
  (!new_list)

let rec check_asn1_scheme_recurse node_ref asn1_container asn1_scheme asn1_nodes = 
  (* Extract information *)
  let (pos, asn1_string, asn1_content, info, encapsulated_values, _) = get_common_fields_from_asn1_value asn1_container in
  let (tag_type, string_info, pc, tag_class, tag_num) = info in
  let (name, current_simplified_representation, embedded_list) = get_tag_from_asn1_simplified_representation asn1_scheme in
  (* Do we have an option type? If yes, we skip the current node and check all the possible sub nodes as options *)
  match asn1_scheme with
  | Option_R(_, _) ->
    (* If at least one of the subschemes is OK we return true and stop there *)
    (* Recurse through the options for the current asn1 value *)
    let returned_value_nodes = ref [] in
    let returned_ret = ref false in 
    let i = ref 0 in
    while !i <= (List.length embedded_list)-1 do
      let option_scheme_to_check = (List.nth embedded_list !i) in
      i := !i + 1;      
      (* Special case for the None_R option where we accept to have nothing *)
      if (compare option_scheme_to_check None_R = 0) && (compare encapsulated_values None = 0) then
        (* If we have a primitive node without anything beneath, we return true *)
        returned_ret := true
      else
        let (ret, nodes) = check_asn1_scheme_recurse node_ref asn1_container option_scheme_to_check asn1_nodes in        
        if ret = true then
          if !returned_ret = false then
            returned_ret := true;
            returned_value_nodes := fuse_nodes_lists !returned_value_nodes nodes;
    done;
    (!returned_ret, !returned_value_nodes)
  | Any_R(_) ->
    (* The Any_R is a special value for anything, return true with the current container *) 
    (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
  | _ ->
    (*** Specific Tags special actions ************************)
    let check_specific_tag = (
      match asn1_scheme  with
      (* Check if the specific tag number indeed corresponds to the one provided in the reference scheme *)
      (* If -1 has been provided, we accept any value                                                    *)
         SpecificTag_R(_, i, _, _, _) ->  if (i != -1) && (i != tag_num) then false else true
        |_ -> true
    ) in
    let check_specific_tag_constructed = (
      match asn1_scheme  with
      (* Check for Specific Tags that the Primitive and Constructed types given in the scheme are respected *)
         SpecificTag_R(_, _, curr_pc, _, _) -> 
           if compare pc Primitive_Constructed = 0 then
             raise(ASN1_Check_Scheme_Error "Internal error: Primitive_Constructed given for SpecificTag_R simplified representation (should be Primitive *OR* Constructed)")
           else
             if compare pc curr_pc = 0 then true else false 
       | _ -> true
    ) in
    if (check_specific_tag = false) || (check_specific_tag_constructed = false) || (current_simplified_representation = None) then
      (false, [])
    else
      (* Here, we check implicit versus exlicit tagging ...                       *)
      (*  - If we have an implicit tagging, we skip the son node                  *)
      (*  - If we have explicit tagging, do continue as usual with regular checks *)
      let check_specific_tag_imlicit = (
        match asn1_scheme with
           SpecificTag_R(_, _, _, implexpl, _) -> if compare implexpl Implicit = 0 then true else false
          |_ -> false
      ) in
      if (check_specific_tag_imlicit = true) && ((List.length embedded_list) <> 0) then
        (* When we have implicit tagging, we check that we have only one ecapsulated value        *)
        (* in the representation scheme ... if this is not the case, the scheme is not consistent *)
        if (List.length embedded_list) > 1 then
          raise(ASN1_Check_Scheme_Error "Internal error: Implicit SpecificTag_R given with more than one encapsulated node")
        else
          (* In order to do a regular pattern matching, we artificially add a parent node to the current *)
          (* representation node, and check the representation against the explicit scheme               *)
          (* This seems somewhat "artificial", however this makes it easy to reuse existing code basis   *)
          let the_embedded_list_elt = List.nth embedded_list 0 in
          let is_any_r = ref false in
          let new_artificial_asn1_value = (try implicit_tag_new_asn1_container_from_representation the_embedded_list_elt encapsulated_values pos asn1_content with
            | ASN1_Not_found -> 
              (* Any_R was found: this means that the node encapsulates anything, return true here *)
              is_any_r := true; Null_V(pos, "", "", asn1_info_from_type Null, None, None, false)
            | ASN1_Check_Scheme_Error(s) -> raise(ASN1_Check_Scheme_Error s)
          ) in
          if !is_any_r = true then
            (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
          else
            let (ret, nodes) = check_asn1_scheme_recurse (List.append node_ref [0]) new_artificial_asn1_value the_embedded_list_elt asn1_nodes in
            (ret, fuse_nodes_lists asn1_nodes (List.append [(node_ref, name, asn1_container)] nodes))
      (*** End of special treatment for Specific Tags **)
      else      
        let current_simplified_representation = Helpers.get current_simplified_representation in      
        (* Do we have a sequence or a set in our simplified representation? If yes, get the number max *)
        (* and instantiate the fully unrolled simplified representation                                *)
        (***********************************************************************************************)
        let (ok, embedded_list) = (
          if (compare tag_type Sequence = 0) || (compare tag_type Set = 0) then
            let (mini, maxi) = get_minmax_from_asn1_simplified_representation asn1_scheme in
            if (mini < 0) || (maxi < 0) || (mini > maxi) then
              raise(ASN1_Check_Scheme_Error "Internal error: bad min and max for SEQUENCE simplified representation")
            else          
              let encapsulated_values_length = (if encapsulated_values = None then 0 else (List.length (Helpers.get encapsulated_values))) in
              (* We adapt the growing factor to the real length of the encapsulated list *)          
              let growing_factor = (            
                if encapsulated_values_length < (List.length embedded_list) then
                  1
                else
                  if (List.length embedded_list) <> 0 then
                    encapsulated_values_length/(List.length embedded_list)
                  else
                    0         
              ) in
              if (growing_factor < mini) || (growing_factor > maxi) then
                (* Make us return false *)
                (false, [])
              else
                if growing_factor = 0 then
                  (true, [])
                else
                  (* Duplicate the embedded list to the length of the current embedded list *)
                  let new_embedded_list = ref [] in
                  for i=0 to growing_factor-1 do
                    new_embedded_list := List.append !new_embedded_list embedded_list;
                  done;
                  (true, !new_embedded_list)
          else
            (true, embedded_list)) in
        (**********************************************************)
        if ok = false then
          (false, [])
        else
          (* Compare the tags at each level between the reference scheme and the current one *)
          if compare tag_type current_simplified_representation <> 0 then
            (* If there is a mismatch, return false *)
            (false, [])
          else
            (* Else, recurse through all the elements or add the current element as a leaf *)
            if ((List.length embedded_list = 0) && (encapsulated_values <> None)) ||
               ((List.length embedded_list <> 0) && (encapsulated_values = None)) then 
              if ((List.length embedded_list <> 0) && (encapsulated_values = None)) then
                (* This is an ending point unless we have an option with Any_R or None_R inside it *)
                (* or if if we have a list of None_R, or if we have one Any_R                      *)
                let ret = ref false in
                let found_none_r = ref 0 in
                let found_any_r = ref 0 in
                for i=0 to (List.length embedded_list)-1 do
                  let the_embedded_list_elt = List.nth embedded_list i in                
                  let sub_embedded_list = (match the_embedded_list_elt with
                      Option_R(_, sub_embedded_list) -> sub_embedded_list
                    | Any_R(_) -> found_any_r := !found_any_r + 1; []
                    | None_R -> found_none_r := !found_none_r + 1; []
                    | _ -> []) in
                  let found_none_any = List.find_all (
                        fun a -> match a with (None_R | Any_R(_)) -> true |_ -> false
                   ) sub_embedded_list in
                   if List.length found_none_any <> 0 then             
                     ret := true
                done;
                if (!ret = true) || ((!found_none_r = 1) && ((List.length embedded_list) = 1)) || (!found_any_r = 1) then
                  (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
                else
                  (false, [])
              else
                (* If we are here, we have an empty embedded list and empty encapsulated value  *)
                (false, [])
            else
              (************* Primitive type ************************************)
              if encapsulated_values = None then
                (* If this is an OID or relative OID, check that it is correct *)
                if compare tag_type OID = 0 then
                  let allowed_oid_list = get_oids_from_asn1_simplified_representation asn1_scheme in
                  if (List.length allowed_oid_list) = 0 then
                    (* No oid provided in the scheme, return true *)
                    (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
                  else
                    (* Oids provided in the scheme, check them *)
                    let current_oid = (match asn1_container with
                       OID_V(_, _, _, _, _, Some (OID_value(oid_array)), _) -> oid_array
                      | _ -> [| |]) in
                    let check = Oids.check_is_oid_in_list current_oid allowed_oid_list in
                    if check = true then
                      (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
                    else
                      (false, [])
                else
                  (true, fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)])
              (************* Constructed type ************************************)
              else            
                let the_encapsulated_values = Helpers.get encapsulated_values in
                if (List.length embedded_list) < (List.length the_encapsulated_values) then
                  (* We return false since the representation must be more exhaustive than the real values *)
                  (false, [])
                else
                  (* Initialize the list to the current node/container *)
                  let returned_value_nodes = ref (fuse_nodes_lists asn1_nodes [(node_ref, name, asn1_container)]) in
                  let returned_ret = ref true in
                  (* This is not a leaf, recurse through the subcontainers *)
                  let i = ref 0 in
                  let j = ref 0 in
                  while !i <= (List.length the_encapsulated_values)-1 do
                    if !j >= (List.length embedded_list) then
                    begin
                      i := !i + 1;
                      returned_ret := !returned_ret && false;
                    end
                    else
                      let the_embedded_list_elt = List.nth embedded_list !j in
                      let (ret, nodes) = check_asn1_scheme_recurse (List.append node_ref [!i]) (List.nth the_encapsulated_values !i) the_embedded_list_elt asn1_nodes in
                      i := !i + 1;
                      j := !j + 1;
                      if ret = false then
                        (match the_embedded_list_elt with
                           Any_R(_) -> ()
                         | Option_R(_, sub_embedded_list) ->
                             (* Check that the option contains an Any_R or a None_R *)
                             let found_none_any = List.find_all (
                               fun a -> match a with (None_R | Any_R(_)) -> true |_ -> false
                             ) sub_embedded_list in
                             if List.length found_none_any = 0 then
                               returned_ret := !returned_ret && false
                             else
                               (* We have found a None_R or Any_R, we REWIND the node *)  
                               i := !i - 1;
                         | _ -> returned_ret := !returned_ret && false
                        )
                      else                    
                        returned_ret := !returned_ret && true;
                        returned_value_nodes := fuse_nodes_lists !returned_value_nodes nodes
                  done;
                  (* If we are here, everything has matched until now *)
                  (* If there are still elements in the embedded_list, they must be Any_R or Option_R with None_R or Any_R inside *)
                  if (!returned_ret = true) && ((List.length embedded_list) > (List.length the_encapsulated_values)) then
                    (* Go through all the elements of the embedded list *)
                    for i=(List.length the_encapsulated_values) to (List.length the_encapsulated_values)-1 do
                      let the_embedded_list_elt = List.nth embedded_list i in
                      (match the_embedded_list_elt with
                         Any_R(_) -> ()
                       | Option_R(_, sub_embedded_list) ->
                           (* Check that the option contains an Any_R or a None_R *)
                           let found_none_any = List.find_all (
                             fun a -> match a with (None_R | Any_R(_)) -> true |_ -> false
                           ) sub_embedded_list in
                           if List.length found_none_any = 0 then
                             returned_ret := !returned_ret && false
                       | _ -> returned_ret := !returned_ret && false
                      )
                    done;
                  if !returned_ret = false then
                    (false, [])
                  else
                    (true, !returned_value_nodes)

let check_asn1_scheme asn1_container asn1_scheme = 
  (* Recurse through the container and get the result *)
  let (check, representation_list) = check_asn1_scheme_recurse [] asn1_container asn1_scheme [] in
  (* Populate the hash table with the ASN1 nodes *)
  let representation_hashtbl = ref (Hashtbl.create 0) in
  List.iter (fun (node_ref, a, b) -> 
    let new_string = Printf.sprintf "%s" a in
    Hashtbl.add !representation_hashtbl new_string (node_ref, b))
  representation_list;
  (* Flatten the hash table by removing collisions since we do not want them *)
  let new_representation_hashtbl = ref (Hashtbl.create 0) in
  let last_key = ref None in
  let key_changed = ref true in
  Hashtbl.iter (
    fun key value ->
    if compare !last_key None = 0 then
      last_key := Some key
    else
      (* Are we changing the key? *)
      if compare (Helpers.get !last_key) key = 0 then
        key_changed := false
      else
        key_changed := true;
        last_key := Some key;
    let found = Hashtbl.find_all !representation_hashtbl key in
    if (List.length found) > 0 then
      (* Are we stuck to the same key? *)
      if !key_changed = true then       
        (* Multiple occurrences, take care of them *)
        (* First, we sort the list depending on the node number *)
        let new_found = List.sort (
          fun value1 value2 ->
            let (node_ref1, _) = value1 in
            let (node_ref2, _) = value2 in
            if (List.length node_ref1) > (List.length node_ref2) then
              (-1)
            else
              if (List.nth node_ref1 (List.length node_ref1 - 1)) > (List.nth node_ref2 (List.length node_ref2 - 1)) then
                (-1)
              else
                (1)
        ) found in
        let num = ref 0 in
        List.iter (
          fun value ->
            let new_key = Printf.sprintf "%s[%d]" key !num in 
            Hashtbl.add !new_representation_hashtbl new_key value;
            num := !num + 1
        ) new_found
      else
        (* Do nothing *)
        ()
    else
      (* Only one occurrence *)
      Hashtbl.add !new_representation_hashtbl key value;
  ) !representation_hashtbl;
  (check, !new_representation_hashtbl)

let sublist be en the_list = 
  let new_list = try (
    Array.to_list (Array.sub (Array.of_list the_list) be (en-be+1))
  ) with _ -> [] in
  (new_list)


(* This function extracts the string of a given field of an ASN1 checked representation      *)
(* from its node position                                                                    *)
let get_asn1_value_from_node_pos asn1_hash_representation node_pos =
  (* Find the element in the hash table *)
  let the_value = ref None in 
  Hashtbl.iter (
    fun key (curr_node_pos, curr_value) ->
      if compare curr_node_pos node_pos = 0 then
        the_value := Some curr_value
      else
        ()
  ) asn1_hash_representation;
  if compare !the_value None = 0 then
    let s = "{" in
    let s = List.fold_left (
      fun curr_s curr_pos -> Printf.sprintf "%s %d" curr_s curr_pos 
    ) s node_pos in
    let s = Printf.sprintf "%s}" s in
    let s = Printf.sprintf "ASN1 helper error: cannot find node at position %s" s in
    raise(ASN1_Helper_Error(s))
  else
    (Helpers.get !the_value)

let get_field_of_asn1_representation_from_node_pos asn1_hash_representation node_pos =
  let the_value = get_asn1_value_from_node_pos asn1_hash_representation node_pos in
  let (_, asn1_string, asn1_content, _, _, _) = get_common_fields_from_asn1_value the_value in
  (asn1_string, asn1_content)


(* This function extracts the string of given fields of an ASN1 checked representation       *)
(* from a name                                                                               *)
let get_asn1_value_from_name asn1_hash_representation node_name =
  (* Find the element in the hash table *)
  let found = Hashtbl.find_all asn1_hash_representation node_name in
  if List.length found = 0 then
    let s = Printf.sprintf "ASN1 helper error: cannot find node with name %s" node_name in
    raise(ASN1_Helper_Error(s))
  else
    if List.length found > 1 then
      let s = Printf.sprintf "ASN1 helper error: found multiple nodes (%d) with name %s" (List.length found) node_name in
      raise(ASN1_Helper_Error(s))
    else
      let (node_pos, value) = (List.hd found) in
      (value)

let get_field_of_asn1_representation_from_name asn1_hash_representation node_name =
  let the_value = get_asn1_value_from_name asn1_hash_representation node_name in
  let (_, asn1_string, asn1_content, _, _, _) = get_common_fields_from_asn1_value the_value in
  (asn1_string, asn1_content)
      
(* This function extracts the node position of given fields of an ASN1 checked representation *)
(* from its name *)
let get_node_pos_of_asn1_representation_from_name asn1_hash_representation node_name =
  (* Find the element in the hash table *)
  let found = Hashtbl.find_all asn1_hash_representation node_name in
  if List.length found = 0 then
    let s = Printf.sprintf "ASN1 helper error: cannot find node with name %s" node_name in
    raise(ASN1_Helper_Error(s))
  else
    if List.length found > 1 then
      let s = Printf.sprintf "ASN1 helper error: found multiple nodes (%d) with name %s" (List.length found) node_name in
      raise(ASN1_Helper_Error(s))
    else
      let (node_pos, value) = (List.hd found) in      
      (node_pos)

(* This function extracts the node name of given fields of an ASN1 checked representation *)
(* from its node position *)
let get_name_of_asn1_representation_from_node_pos asn1_hash_representation node_pos =
  (* Find the element in the hash table *)
  let the_name = ref None in 
  Hashtbl.iter (
    fun key (curr_node_pos, curr_value) ->
      if compare curr_node_pos node_pos = 0 then  
        the_name := Some key
      else
        ()
  ) asn1_hash_representation;
  if compare !the_name None = 0 then
    let s = "{" in
    let s = List.fold_left (
      fun curr_s curr_pos -> Printf.sprintf "%s %d" curr_s curr_pos 
    ) s node_pos in
    let s = Printf.sprintf "%s}" s in
    let s = Printf.sprintf "ASN1 helper error: cannot find node at position %s" s in
    raise(ASN1_Helper_Error(s))
  else
    (Helpers.get !the_name)

(* This function takes as input a node in an ASN1 representation format list and finds its father *)
let get_father_node representation_list node_ref = 
  let father = List.find (
    fun (nref, a, b) -> 
      if List.length node_ref <= 1 then
        if compare nref [] = 0 then true else false
      else
        if compare nref (sublist 0 (List.length node_ref - 2) node_ref) = 0 then true else false
  ) representation_list in
  (father)

(* This function takes as input a node in an ASN1 representation format list and finds all its fathers *)
(* along the path to the root                                                                          *)
let rec get_all_father_nodes_rec representation_list node_ref current_fathers =
  (* If this is the root, we are done *)
  if compare node_ref [] = 0 then
    (current_fathers)
  else
    let (father_node_ref, father_name, father_value) = get_father_node representation_list node_ref in
    (get_all_father_nodes_rec representation_list father_node_ref (List.concat [current_fathers; [(father_node_ref, father_name, father_value)]]))

let get_all_father_nodes representation_list node_ref =
  (get_all_father_nodes_rec representation_list node_ref [])

(* Recursively print a checked ASN1 representation *)
let sprint_node_pos node_pos =
  let s = List.fold_left (
    fun a b -> (Printf.sprintf "%s%d, " a b)
  ) "" node_pos in
  (s)

let sprint_asn1_value asn1_label asn1_value =
  let (pos, asn1_string, asn1_content, info, encapsulated_values, _) = get_common_fields_from_asn1_value asn1_value in
  let (tag_type, string_info, pc, tag_class, tag_num) = info in
  let real_value = get_real_type_from_asn1_value asn1_value in
  let sreal_value = (
    if real_value = None then
      Printf.sprintf "%s (%s, %d)\n" asn1_label string_info pos
    else
      match (Helpers.get real_value) with
        OID_value(x) -> Printf.sprintf "%s (%s, %d): /%s/\n" asn1_label string_info pos (Oids.get_name_from_oid x Oids.oids)
      | Printable_value(x) -> Printf.sprintf "%s (%s, %d): '%s'\n" asn1_label string_info pos x
      |_ -> Printf.sprintf "%s (%s, %d)\n" asn1_label string_info pos
  ) in
  (sreal_value)


let rec print_checked_asn1_scheme asn1_hash_representation node_pos =
  (* Handle the indentation with the node_pos size *)
  let indent = ref "" in
  for i = 0 to List.length node_pos do
    if (i = List.length node_pos) && (List.length node_pos <> 0) then
      indent := Printf.sprintf "%s|-" !indent
    else
      indent := Printf.sprintf "%s  " !indent
  done;
  (* Print the current node *)
  let node_content = (try Some (get_asn1_value_from_node_pos asn1_hash_representation node_pos) with
    _ -> None) in
  (* Does the node exist? *)
  let is_node_existing = (match node_content with
      (* The node does not exist, return to upper level *)
    | None -> (false)
      (* The node exists, print it *)
    | Some(asn1_value) -> 
      Printf.printf "%s%s" !indent (sprint_asn1_value (get_name_of_asn1_representation_from_node_pos asn1_hash_representation node_pos) asn1_value);
      (true)
  ) in
  if is_node_existing = false then
    (true)
  else
    (* Recursively call all the possible childs *)
    let not_found = ref false in
    let child_index = ref 0 in
    while !not_found = false do
      not_found := (try print_checked_asn1_scheme asn1_hash_representation (List.append node_pos [!child_index]) with
        | _ -> true
      );
      child_index := !child_index + 1;
    done;
    (false)

let print_checked_asn1_scheme asn1_hash_representation =
  let _ = print_checked_asn1_scheme asn1_hash_representation [] in
  ()

(***********************************************************)
(****** Construction of ASN1 values ************************)
(****** For now, we only handle DER representations ********)

(* Each constructed value contains either a raw DER value,           *)
(* a raw string value for basic types or a list of encapsulated ASN1 *)
(* a constructed values                                              *) 
type asn1_construct_representation =
  | Boolean_C of string
  | Integer_C of string
  | Enumerated_C of string
  | Real_C of string
  | Null_C
  | OID_C of string
  | RelativeOID_C of string
  | Bitstring_C of string
  | Octetstring_C of string
  | ObjectDescriptor_C of string 
  | NumericString_C of string
  | PrintableString_C of string
  | TeletexString_C of string
  | VideotexString_C of string
  | VisibleString_C of string
  | IA5String_C of string
  | GraphicString_C of string
  | GeneralString_C of string
  | UniversalString_C of string
  | BMPString_C of string
  | UTF8String_C of string
  | CharString_C of string
  | UTCTime_C of string
  | GeneralizedTime_C of string
  (* Constructed types *)
  | Sequence_C of string * asn1_construct_representation list
  | Set_C of string * asn1_construct_representation list
  | Embedded_PDV_C of string * asn1_construct_representation list
  | External_C of string * asn1_construct_representation list
  | SpecificTag_C of string * asn1_construct_representation list * int * asn1_tag_type * asn1_tag_explicit_implicit
  | None_C

let asn1_info_from_constructed_type the_type = 
  match the_type with
      Boolean_C(s) -> (Boolean, "Boolean", Primitive, Universal, 0x1, s, None)
    | Integer_C(s) -> (Integer, "Integer", Primitive, Universal, 0x2, s, None)
    | Enumerated_C(s) -> (Enumerated, "Enumerated", Primitive, Universal, 0xa, s, None)
    | Real_C(s) -> (Real, "Real", Primitive, Universal, 0x9, s, None)
    | Bitstring_C(s) -> (Bitstring, "Bitstring", Primitive_Constructed, Universal, 0x3, s, None)
    | Octetstring_C(s) -> (Octetstring, "Octetstring", Primitive_Constructed, Universal, 0x4, s, None)
    | Null_C -> (Null, "Null", Primitive, Universal, 0x5, "", None)
    | OID_C(s) -> (OID, "OID", Primitive, Universal, 0x6, s, None)
    | RelativeOID_C(s) -> (RelativeOID, "RelativeOID", Primitive, Universal, 0xd, s, None)
    | ObjectDescriptor_C(s) -> (ObjectDescriptor, "ObjectDescriptor", Primitive_Constructed, Universal, 0x7, s, None)
    | NumericString_C(s) -> (NumericString, "NumericString", Primitive_Constructed, Universal, 0x12, s, None)
    | PrintableString_C(s) -> (PrintableString, "PrintableString", Primitive_Constructed, Universal, 0x13, s, None)
    | TeletexString_C(s) -> (TeletexString, "TeletexString", Primitive_Constructed, Universal, 0x14, s, None)
    | VideotexString_C(s) -> (VideotexString, "VideotexString", Primitive_Constructed, Universal, 0x15, s, None)
    | VisibleString_C(s) -> (VisibleString, "VisibleString", Primitive_Constructed, Universal, 0x1a, s, None)
    | IA5String_C(s) -> (IA5String, "IA5String", Primitive_Constructed, Universal, 0x16, s, None)
    | GraphicString_C(s) -> (GraphicString, "GraphicString", Primitive_Constructed, Universal, 0x19, s, None)
    | GeneralString_C(s) -> (GeneralString, "GeneralString", Primitive_Constructed, Universal, 0x1b, s, None)
    | UniversalString_C(s) -> (UniversalString, "UniversalString", Primitive_Constructed, Universal, 0x1c, s, None)
    | BMPString_C(s) -> (BMPString, "BMPString", Primitive_Constructed, Universal, 0x1e, s, None)
    | UTF8String_C(s) -> (UTF8String, "UTF8String", Primitive_Constructed, Universal, 0xc, s, None)
    | CharString_C(s) -> (CharString, "CharString", Primitive_Constructed, Universal, 0x1d , s, None)
    | UTCTime_C(s) -> (UTCTime, "UTCTime", Primitive_Constructed, Universal, 0x17, s, None)
    | GeneralizedTime_C(s) -> (GeneralizedTime, "GeneralizedTime", Primitive_Constructed, Universal, 0x18, s, None)
    (* Constructed types *)
    | Sequence_C(s, encapsulated) -> 
      if compare encapsulated [] = 0 then
        (Sequence, "Sequence", Constructed, Universal, 0x10, s, None)
      else
        (Sequence, "Sequence", Constructed, Universal, 0x10, s, Some encapsulated)
    | Set_C(s, encapsulated) -> 
      if compare encapsulated [] = 0 then
        (Set, "Set", Constructed, Universal, 0x11, s, None)
      else
        (Set, "Set", Constructed, Universal, 0x11, s, Some encapsulated)
    | External_C(s, encapsulated) -> 
      if compare encapsulated [] = 0 then
        (External, "External", Constructed, Universal, 0x8, s, None)
      else
        (External, "External", Constructed, Universal, 0x8, s, Some encapsulated)
    | Embedded_PDV_C(s, encapsulated) -> 
      if compare encapsulated [] = 0 then
        (Embedded_PDV, "Embedded_PDV", Constructed, Universal, 0xb, s, None)
      else
        (Embedded_PDV, "Embedded_PDV", Constructed, Universal, 0xb, s, Some encapsulated)
    | SpecificTag_C(s, encapsulated, tag, pc, implexl) -> 
      if compare encapsulated [] = 0 then
        (SpecificTag, "SpecificTag", pc, Context, tag, s, None)
      else
        (SpecificTag, "SpecificTag", pc, Context, tag, s, Some encapsulated)
    (* Empty node *)
    | None_C -> (Null, "None", Primitive, Universal, 0x0, "", None)

IFDEF OCAML_NO_BYTES_MODULE THEN
(* Transform a given length to a big endian string *)
let int_to_big_endian_string in_int =
  (* We only handle length encoded on 4 bytes maximum *)
  (* Compute the number of bytes needed *)
  let num_of_bytes = (
    if in_int < 256 then
      (1)
    else
      if in_int < 65536 then
        (2)
      else
        if in_int < 16777216 then
          (3)
        else 
          (4)
  ) in
  let out_string = ref (Bytes.create num_of_bytes) in
  for i=0 to (num_of_bytes-1) do
    !out_string.[i] <- Char.chr ((in_int lsr (8*(num_of_bytes - 1 - i))) land 0xff);
  done;
  (!out_string)
ENDIF
IFNDEF OCAML_NO_BYTES_MODULE THEN
(* Transform a given length to a big endian string *)
let int_to_big_endian_string in_int =
  (* We only handle length encoded on 4 bytes maximum *)
  (* Compute the number of bytes needed *)
  let num_of_bytes = (
    if in_int < 256 then
      (1)
    else
      if in_int < 65536 then
        (2)
      else
        if in_int < 16777216 then
          (3)
        else 
          (4)
  ) in
  let out_string = ref (Bytes.create num_of_bytes) in
  for i=0 to (num_of_bytes-1) do
    Bytes.set !out_string i (Char.chr ((in_int lsr (8*(num_of_bytes - 1 - i))) land 0xff));
  done;
  (Bytes.to_string !out_string)
ENDIF


(* Build an ASN1 block at first level given its type and its content *)
let asn1_build_block asn1_type given_tag = 
  (* First, we get the tag and other information from the type *)
  let (the_type, info, pc, the_class, tag, given_content, encapsulated) = asn1_info_from_constructed_type asn1_type in
  if compare encapsulated None <> 0 then
    (* We cannot process a block with encapsulated values, raise an error *)
    raise(ASN1_Construct_Error("ASN1 construct error: given build block contains both a string and an encapsulated content"))
  else
    (* Do we have an empty node with a None_C value? *)
    if compare info "None" = 0 then
      (* Return the empty string *)
      ("")
    else
      (* Forge the ASN1 header from the information we have *)
      (* [Class | P/C | Tag ] *)
      let identifier_octet = (
        if compare the_type SpecificTag = 0 then
          (* For specific tags, we take the constructing identifier byte as is *)
          (* However, we return an error if the class tag is not properly set *)
          let tag_class = (given_tag lsr 6) in
          if tag_class = 0 then
            let s = Printf.sprintf "ASN1 construct error: given specific tag %d corresponds to a native ASN1 type" given_tag in
            raise(ASN1_Construct_Error(s))
          else
            (* The identifier octet is the tag as is *)
           (String.make 1 (Char.chr given_tag))
        else
            (* If we have native ASN1 types, we construct the proper tag *)
            (* Since we only handle DER, the only really constructed types are the ones *)
            (* that are only constructed                                                *)
            if compare pc Constructed = 0 then
              (String.make 1 (Char.chr (tag lxor (0x1 lsl 5))))
            else
              (String.make 1 (Char.chr tag))
      ) in
      let length_octets = (
        (* We get the length of the raw content *)
        let content_length = String.length given_content in
        (* Depending on the content size, we might encode the length in short or long form *)
        if content_length < 128 then
          (* Encode the length in its short form *)
          (String.make 1 (Char.chr content_length))
        else
          (* Encode the length in its long form *)
          (* Get the number of bytes encoding the content *)
          let the_length_string = int_to_big_endian_string content_length in
          (* Encode it in the length octet *)
          let length_octet = String.make 1 (Char.chr ((String.length the_length_string) lxor 0x80)) in
          (* Concatenate the strings *)
          (length_octet ^ the_length_string)
      ) in
      (* Concatenate the identifier information, the length strings and the content *)
      (identifier_octet ^ length_octets ^ given_content)


let rec build_asn1_representation asn1_constructed_scheme current_asn1_result =
   (* We have three cases:                                                                *)
   (*   - This is a constructed node where the ASN1 string representation is given (leaf) *)
   (*   - This is a primitive node that contains a native ASN1 primitive type (leaf)      *)
   (*   - This is a constructed node that contains other nodes (we have to recurse)       *)
   let (the_type, the_info, pc, the_class, tag, given_content, encapsulated) = asn1_info_from_constructed_type asn1_constructed_scheme in
   (* Raise an exception if a string is given as well as an encapsulated content *)
   if (compare given_content "" <> 0) && (compare encapsulated None <> 0) then
     raise(ASN1_Construct_Error("ASN1 construct error: an ASN1 build block contains both a string and an encapsulated content"))
   else
     match the_type with
      (Sequence | Set | External | Embedded_PDV | SpecificTag) ->
        (* Case where we have a primirive specific tag *)
        if (compare the_type SpecificTag = 0) && (compare pc Primitive = 0) then
          (* We call the block creator and return the concatenation *)
          (* of the strings                                         *)
          let result_string = asn1_build_block asn1_constructed_scheme tag in
          (current_asn1_result ^ result_string)         
        else
          (* The type is constructed *)
          (* Check if a string is given, or if we have to recurse *)       
          if (compare given_content "" <> 0) || (compare encapsulated None = 0) then
            (* We have a string, call the block creator *)
            let result_string = asn1_build_block asn1_constructed_scheme tag in
            (current_asn1_result ^ result_string)
          else
            (* We have an encapsulated content, get it and recurse *)
            let encapsulated_value = Helpers.get encapsulated in
            let result_string = ref "" in          
            let _ = List.iter (
              fun elem ->
                result_string := build_asn1_representation elem !result_string;
            ) encapsulated_value in
            (* Once we have the string representing the encapsulated values, we take *)
            (* care of the constructed type                                          *)
            let resolved_asn1_constructed_scheme = (
              match the_type with
                  Sequence -> Sequence_C(!result_string, [])
                | Set -> Set_C(!result_string, [])
                | External -> External_C(!result_string, [])
                | Embedded_PDV -> Embedded_PDV_C(!result_string, [])
                | SpecificTag -> SpecificTag_C(!result_string, [], tag, pc, Explicit) 
                | _ -> (* Should not happen *) raise(ASN1_Construct_Error("ASN1 construct error: got bad tag type for constructed types"))
            ) in
            (build_asn1_representation resolved_asn1_constructed_scheme current_asn1_result)
      |_ -> 
        (* The type is primitive *)
        (* We call the block creator and return the concatenation *)
        (* of the strings                                         *)
        let result_string = asn1_build_block asn1_constructed_scheme tag in
        (current_asn1_result ^ result_string)

(*** Helpers to construct strings from primitive ASN1 types *)
(* Helper for boolean values *)
let boolean_to_asn1_string boolean_value tag_type = 
  match tag_type with
      Boolean ->
      if boolean_value = false then
        (String.make 1 (Char.chr 0))
      else
        (String.make 1 (Char.chr 1))
     |_ -> raise(ASN1_Construct_Error("ASN1 construct boolean helper: trying to construct a string from a non boolean tag"))

(* Helper for OID *)
(* Takes an integer as input and divides it in base 128 *)
(* Gives an array of integers as output                 *)
(* FIXME: this is the naive and suboptimal way ...      *)
let divide_base integer base =
  (* Find the greatest 128 power in the integer *)
  let i = ref 0 in
  let res = ref (integer/(pow 1 ( * ) base !i)) in
  while !res >= 1  do
    i := !i + 1;
    res := (integer/(pow 1 ( * ) base !i));
  done;
  if !i <> 0 then
    i := !i - 1;
  (* We have the max power, now compute the coefficients *)
  let out_array = ref (Array.make (!i+1) 0) in
  let remaining = ref integer in
  for power = !i downto 0 do
    !out_array.(!i - power) <- (!remaining/(pow 1 ( * ) base power));
    remaining := !remaining - ((!remaining/(pow 1 ( * ) base power)) * (pow 1 ( * ) base power));
  done;
  (!out_array)

(* Translate an OID (integer array) to a string *)
let get_string_from_oid oid_value = 
  let out_string = ref "" in
  if Array.length oid_value > 2 then
    (* Check that first value is 0, 1, or 2 *)
    let first_value = oid_value.(0) in
    if (first_value > 2) || (first_value < 0) then
      let s = Printf.sprintf "ASN1 construct OID helper: first value %d of OID is > 2 or < 0" first_value in
      raise(ASN1_Construct_Error(s))
    else
      let second_value = oid_value.(1) in
      if (second_value > 39) || (second_value < 0) then
        let s = Printf.sprintf "ASN1 construct OID helper: second value %d of OID is > 39 or < 0" second_value in
        raise(ASN1_Construct_Error(s))
      else
        (* Encode first and second values in one octet *)
        out_string := !out_string ^ (String.make 1 (Char.chr ((40*first_value) + second_value)));
        for i = 2 to (Array.length oid_value - 1) do
          let value = oid_value.(i) in
            (* Encode the value in base 128 bytes *)
            let array_divide = divide_base value 128 in
            let encoding_string = ref "" in
            for i = 0 to ((Array.length array_divide)-1) do
              let encoding_byte = (
                (* If last byte, no MSB set *)              
                if i = ((Array.length array_divide)-1) then
                  (array_divide.(i))
                else
                  (array_divide.(i) lxor 0x80)
              ) in
              encoding_string := !encoding_string ^ (String.make 1 (Char.chr encoding_byte));
            done;
            out_string := !out_string ^ !encoding_string;
        done;
        (!out_string)
  else
    let s = Printf.sprintf "ASN1 construct OID helper: OID length %d is < 2, which is not conforming to the standard ..." (Array.length oid_value) in
    raise(ASN1_Construct_Error(s))

(* Helper for OID string *)
let oid_name_to_asn1_string oid_name tag_type = 
  match tag_type with
    (OID | RelativeOID) ->
      (* First, get the OID associated to the string *)
      let oid_value_list = Oids.get_oids_from_name oid_name Oids.oids in
      if (List.length oid_value_list) = 0 then
        let s = Printf.sprintf "ASN1 construct OID helper: given OID name %s is not a regular OID" oid_name in
        raise(ASN1_Construct_Error(s))
      else
        let oid_value = List.hd oid_value_list in
        (get_string_from_oid oid_value)
    |_ -> raise(ASN1_Construct_Error("ASN1 construct OID helper: trying to construct a string from a non OID or Relative_OID tag"))

let oid_value_to_asn1_string oid_value tag_type = 
  match tag_type with
    (OID | RelativeOID) ->
       (get_string_from_oid oid_value)
    |_ -> raise(ASN1_Construct_Error("ASN1 construct OID helper: trying to construct a string from a non OID or Relative_OID tag"))

IFDEF OCAML_NO_BYTES_MODULE THEN
(* Helper for ASN1 bitstring and octetstring *)
let bitstring_to_asn1_string bitstring length tag_type =
  match tag_type with
     Bitstring ->
       if length > (8*(String.length bitstring)) then
         let s = Printf.sprintf "ASN1 construct Bitstring helper: bad Bitstring length %d while the bytes length is %d" length (8*(String.length bitstring)) in
         raise(ASN1_Construct_Error(s))
       else
         let real_length = (
           if (length mod 8) = 0 then
             (length/8)
           else
             ((length/8)+1)
         ) in
         let new_string = ref (String.sub bitstring 0 real_length) in
         (* Check the length and get the number of padding bits *)
         let padding_bits_num = (8 - (length mod 8)) mod 8 in
         let padding_mask = ref 0 in
         for i = 7 downto padding_bits_num do
           padding_mask := !padding_mask lxor (0x1 lsl i);
         done;
         (* Pad the last byte of the string *)
         !new_string.[String.length !new_string - 1] <- Char.chr ((Char.code !new_string.[String.length !new_string - 1]) land !padding_mask);
         new_string := (String.make 1 (Char.chr padding_bits_num)) ^ !new_string;
         (!new_string)
    |_ -> raise(ASN1_Construct_Error("ASN1 construct Bitstring helper: trying to construct a string from a non Bitstring tag"))

let represented_bitstring_to_packed_bitstring input =
  (* Compute the target length *)
  let length = (
    if (String.length input) mod 8 = 0 then
      ((String.length input)/8)
    else
      (((String.length input)/8)+1)
  ) in
  let out_string = ref (String.make length (Char.chr 0)) in
  (* Parse the given bitstring and pack it *)
  for i = 0 to (String.length input - 1) do
    let bit = (
      if input.[i] = '1' then
        (0x1)
      else
        if input.[i] = '0' then
          (0x0)
        else
          let s = Printf.sprintf "ASN1 construct Bitstring helper: given character %c is not a bit (must be either 0 or 1)" input.[i] in
          raise(ASN1_Construct_Error(s))
    ) in
    !out_string.[i/8] <- Char.chr ((Char.code !out_string.[i/8]) lxor (bit lsl (7-(i mod 8))));
  done;
  (!out_string)
ENDIF
IFNDEF OCAML_NO_BYTES_MODULE THEN
(* Helper for ASN1 bitstring and octetstring *)
let bitstring_to_asn1_string bitstring length tag_type =
  match tag_type with
     Bitstring ->
       if length > (8*(String.length bitstring)) then
         let s = Printf.sprintf "ASN1 construct Bitstring helper: bad Bitstring length %d while the bytes length is %d" length (8*(String.length bitstring)) in
         raise(ASN1_Construct_Error(s))
       else
         let real_length = (
           if (length mod 8) = 0 then
             (length/8)
           else
             ((length/8)+1)
         ) in
         let new_string = ref (Bytes.of_string (String.sub bitstring 0 real_length)) in
         (* Check the length and get the number of padding bits *)
         let padding_bits_num = (8 - (length mod 8)) mod 8 in
         let padding_mask = ref 0 in
         for i = 7 downto padding_bits_num do
           padding_mask := !padding_mask lxor (0x1 lsl i);
         done;
         (* Pad the last byte of the string *)
         Bytes.set !new_string (Bytes.length !new_string - 1) (Char.chr ((Char.code (Bytes.get !new_string (Bytes.length !new_string - 1))) land !padding_mask));
         new_string := Bytes.cat (Bytes.make 1 (Char.chr padding_bits_num)) !new_string;
         (Bytes.to_string !new_string)
    |_ -> raise(ASN1_Construct_Error("ASN1 construct Bitstring helper: trying to construct a string from a non Bitstring tag"))

let represented_bitstring_to_packed_bitstring input =
  (* Compute the target length *)
  let length = (
    if (String.length input) mod 8 = 0 then
      ((String.length input)/8)
    else
      (((String.length input)/8)+1)
  ) in
  let out_string = ref (Bytes.of_string (String.make length (Char.chr 0))) in
  (* Parse the given bitstring and pack it *)
  for i = 0 to (String.length input - 1) do
    let bit = (
      if input.[i] = '1' then
        (0x1)
      else
        if input.[i] = '0' then
          (0x0)
        else
          let s = Printf.sprintf "ASN1 construct Bitstring helper: given character %c is not a bit (must be either 0 or 1)" input.[i] in
          raise(ASN1_Construct_Error(s))
    ) in
    Bytes.set !out_string (i/8) (Char.chr ((Char.code (Bytes.get !out_string (i/8))) lxor (bit lsl (7-(i mod 8)))));
  done;
  (Bytes.to_string !out_string)
ENDIF

(* Date and time creation helpers *)
let time_to_asn1_string the_time tag_type = 
  (* Extract the data from the time *)
  match tag_type with
     UTCTime -> 
      (the_time)
    |GeneralizedTime ->
      (the_time)
    |_ -> raise(ASN1_Construct_Error("ASN1 construct TIME helper: trying to construct a string from a non UTCTime or GeneralizedTime tag"))
 

(***** Transformation of an existing ASN1 representation to a constructed representation ***)
(***** so that it can be dumped                                                          ***)
let hash_table_to_list hash_tbl = 
  let the_list = Hashtbl.fold (
    fun key d curr_list ->
      (List.concat [curr_list; [(key, d)]])
  ) hash_tbl [] in
  (the_list)

let list_to_hash_table the_list = 
  let the_hash_table = List.fold_left (
    fun curr_hash_tbl (a, b) ->
      let _ = Hashtbl.add curr_hash_tbl a b in
      (curr_hash_tbl)
  ) (Hashtbl.create 0) the_list in
  (the_hash_table)

(***** Mofication of an existing ASN1 representation helpers ****)
let rec asn1_value_to_constructed_asn1 asn1_value =
  match asn1_value with
  (* Primitive types *)
  | Boolean_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> 
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Boolean_C(content_string)
  | Integer_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> 
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Integer_C(content_string)
  | Real_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> 
     if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Real_C(content_string)
  | Enumerated_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Enumerated_C(content_string)
  | OID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      OID_C(content_string)
  | RelativeOID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      RelativeOID_C(content_string)
  | Null_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Null_C
  (* Possibly constructed type *)
  | Bitstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Bitstring_C(content_string)
  | Octetstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      Octetstring_C(content_string)
  | ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      ObjectDescriptor_C(content_string)
  | NumericString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      NumericString_C(content_string)
  | PrintableString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      PrintableString_C(content_string)
  | TeletexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      TeletexString_C(content_string)
  | VideotexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      VideotexString_C(content_string)
  | VisibleString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      VisibleString_C(content_string)
  | IA5String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      IA5String_C(content_string)
  | GraphicString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      GraphicString_C(content_string)
  | GeneralString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      GeneralString_C(content_string)
  | UniversalString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      UniversalString_C(content_string)
  | BMPString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      BMPString_C(content_string)
  | UTF8String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      UTF8String_C(content_string)
  | CharString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      CharString_C(content_string)
  | UTCTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      UTCTime_C(content_string)
  | GeneralizedTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->  
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      GeneralizedTime_C(content_string)
  (*** Constructed types ***)
  (*** Depending on the fact that the field has been modified or not, we recurse or put a straight string value *)
  | Sequence_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> 
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      (* Since it is a constructed type, recurse until we have a fully constructed stuff *)
      if (is_modified = true) || (compare constructed_content None = 0) then
        Sequence_C(content_string, [])
      else
        let constructed_list = List.map (
          fun value -> asn1_value_to_constructed_asn1 value
        ) (Helpers.get constructed_content) in
        Sequence_C("", constructed_list)
  | Set_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      (* Since it is a constructed type, recurse until we have a fully constructed stuff *)
      if (is_modified = true) || (compare constructed_content None = 0) then
        Set_C(content_string, [])
      else
        let constructed_list = List.map (
          fun value -> asn1_value_to_constructed_asn1 value
        ) (Helpers.get constructed_content) in
        Set_C("", constructed_list)
  | External_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      (* Since it is a constructed type, recurse until we have a fully constructed stuff *)
      if (is_modified = true) || (compare constructed_content None = 0) then
        External_C(content_string, [])
      else
        let constructed_list = List.map (
          fun value -> asn1_value_to_constructed_asn1 value
        ) (Helpers.get constructed_content) in
        External_C("", constructed_list)
  | Embedded_PDV_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) ->
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      (* Since it is a constructed type, recurse until we have a fully constructed stuff *)
      if (is_modified = true) || (compare constructed_content None = 0) then
        Embedded_PDV_C(content_string, [])
      else
        let constructed_list = List.map (
          fun value -> asn1_value_to_constructed_asn1 value
        ) (Helpers.get constructed_content) in
        Embedded_PDV_C("", constructed_list)
  | SpecificTag_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> 
    if (is_modified = true) && (compare asn1_string "None" = 0) then
      (* The node must be removed *)
      None_C
    else
      (* Keep the node *)
      let (_, _, tag_type, tag_class, tag_num) = tag_info in
      let tag_type_num = (match tag_type with
          Primitive -> 0x0
        | Constructed -> 0x20
        | _ -> raise(ASN1_Construct_Error("ASN1 construct error: got a SpecificTag_V with Primitive_Constructed type, this should not happen ...")) 
      ) in
      let tag_class_num = (match tag_class with
          Universal -> 0x0
        | Application -> 0x40
        | Context -> 0x80
        | Private -> 0xc0
      ) in
      let tag_num = (tag_num lxor tag_type_num) lxor tag_class_num in
      if compare tag_type Primitive = 0 then 
        (* If we have a primitive specific tag, this is it *)
        SpecificTag_C(content_string, [], tag_num, Primitive, Explicit)
      else
        (* Since it is a constructed type, recurse until we have a fully constructed stuff *)
        if (is_modified = true) || (compare constructed_content None = 0) then
          SpecificTag_C(content_string, [], tag_num, Constructed, Explicit)
        else
          let constructed_list = List.map (
            fun value -> asn1_value_to_constructed_asn1 value
          ) (Helpers.get constructed_content) in
          SpecificTag_C("", constructed_list, tag_num, Constructed, Explicit)

let set_string_of_asn1_value value the_new_string =
  (* If the string is None, this means we want to remove the node *)
  let check_removal = (
    if compare the_new_string None = 0 then
      "None"
    else
      ""
  ) in
  let the_new_content_string = (
    if compare the_new_string None = 0 then
      ""
    else
      Helpers.get the_new_string
  ) in
  match value with
  | Boolean_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Boolean_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Integer_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Integer_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Enumerated_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Enumerated_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Real_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Real_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Bitstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Bitstring_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Octetstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Octetstring_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Null_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Null_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Sequence_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Sequence_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Set_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Set_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | OID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> OID_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | RelativeOID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> RelativeOID_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> ObjectDescriptor_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | External_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> External_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | Embedded_PDV_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Embedded_PDV_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | NumericString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> NumericString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | PrintableString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> PrintableString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | TeletexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> TeletexString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | VideotexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> VideotexString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | VisibleString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> VisibleString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | IA5String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> IA5String_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | GraphicString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GraphicString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | GeneralString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GeneralString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | UniversalString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UniversalString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | BMPString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> BMPString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | UTF8String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UTF8String_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | CharString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> CharString_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | UTCTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UTCTime_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | GeneralizedTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GeneralizedTime_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)
  | SpecificTag_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> SpecificTag_V(pos, check_removal, the_new_content_string, tag_info, None, real_type, true)


let set_sub_nodes_of_asn1_value value sub_nodes_list =
  match value with
  | Boolean_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Boolean_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Integer_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Integer_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Enumerated_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Enumerated_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Real_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Real_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Bitstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Bitstring_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Octetstring_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Octetstring_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Null_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Null_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Sequence_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Sequence_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Set_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Set_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | OID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> OID_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | RelativeOID_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> RelativeOID_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> ObjectDescriptor_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | External_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> External_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | Embedded_PDV_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> Embedded_PDV_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | NumericString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> NumericString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | PrintableString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> PrintableString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | TeletexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> TeletexString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | VideotexString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> VideotexString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | VisibleString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> VisibleString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | IA5String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> IA5String_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | GraphicString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GraphicString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | GeneralString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GeneralString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | UniversalString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UniversalString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | BMPString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> BMPString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | UTF8String_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UTF8String_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | CharString_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> CharString_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | UTCTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> UTCTime_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | GeneralizedTime_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> GeneralizedTime_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)
  | SpecificTag_V(pos, asn1_string, content_string, tag_info, constructed_content, real_type, is_modified) -> SpecificTag_V(pos, asn1_string, content_string, tag_info, sub_nodes_list, real_type, is_modified)



(*** This function finds a node in an asn1 value, modifies it and returns the new asn1 value *)
let rec modify_asn1_node asn1_root_value node_pos curr_node_pos string_value_option =
  (* Recurse through all the nodes *)
  let (pos, asn1_string, content_string, tag_info, constructed_content, is_modified) = get_common_fields_from_asn1_value asn1_root_value in
  (* Is the node the one concerned by the modification? *)
  if compare node_pos curr_node_pos = 0 then
    (*i If yes, modify the value and return *)
    (set_string_of_asn1_value asn1_root_value string_value_option)
  else
    (* This node does not concern us, recurse through all the subnodes *)
    if compare constructed_content None = 0 then
      (* No containing stuff, return the node as is *)
      (asn1_root_value)
    else
      (* Recurse through inculded nodes *)
      let base = ref 0 in
      let new_list = ref [] in
      List.iter (
        fun curr_node ->
          let new_curr_node_pos = List.concat [curr_node_pos; [!base]] in
          let new_node = modify_asn1_node curr_node node_pos new_curr_node_pos string_value_option in
          new_list := List.concat [!new_list; [new_node]];
          base := !base + 1;
      ) (Helpers.get constructed_content);
      (* Return the freshly constructed node *) 
      (set_sub_nodes_of_asn1_value asn1_root_value (Some !new_list))

(* This function finds the root value in an ASN1 hash representation *)
(* and returns its reference                                         *)
let find_root_in_asn1_representation asn1_hash_representation =
  let asn1_list_representation = hash_table_to_list asn1_hash_representation in
  let (root_key, (root_node_pos, root_value)) = List.find (
    fun (key, (node_pos, value)) ->
      if compare node_pos [] = 0 then true else false
  ) asn1_list_representation in
  (root_value)


let modify_field_of_asn1_representation_from_node_pos asn1_hash_representation node_pos new_value_string =
  (* Find the root value *)
  let root_value = find_root_in_asn1_representation asn1_hash_representation in
  (* Now modify it *)
  let new_root_value = modify_asn1_node root_value node_pos [] new_value_string in
  (* And replace the root node in the hash table *)
  let copy_asn1_hash_representation = Hashtbl.copy asn1_hash_representation in
  let _ = Hashtbl.iter (
    fun key (node_pos, value) ->
      if compare node_pos [] = 0 then
        Hashtbl.replace copy_asn1_hash_representation key (node_pos, new_root_value)
      else
        ()
  ) asn1_hash_representation in
  (copy_asn1_hash_representation)

let modify_field_of_asn1_representation_from_name asn1_hash_representation name new_value_string =
  (* Find the element in the hash table *)
  let (node_pos, node_value) = (try Hashtbl.find asn1_hash_representation name 
    with _ -> let s = Printf.sprintf "ASN1 representation modification error when searching field %s" name in
              raise(ASN1_Construct_Error(s))) in
  (modify_field_of_asn1_representation_from_node_pos asn1_hash_representation node_pos new_value_string)


let dump_asn1_modified_representation asn1_hash_representation = 
  (* Transform the hash table to a constructed representation *)
  let root_value = find_root_in_asn1_representation asn1_hash_representation in
  let constructed_value = asn1_value_to_constructed_asn1 root_value in
  let out_string = build_asn1_representation constructed_value "" in
  (out_string)
