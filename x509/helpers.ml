(* ANS.1 helpers *)
(* WARNING: this is a beta version    *)
(* Improvement and fixes are expected *)


(** Generic function to get the value of an option **)
let get = function
  | Some x -> x
  | None   -> raise (Invalid_argument "Option.get")

let print_hex a =
  Printf.printf "%02x" (int_of_char a);
  ()

let print_hex_array a =
  Array.iter print_hex a;
  Printf.printf "\n";
  ()

let string_to_char_array s =
  (Array.init (String.length s) (fun i -> s.[i]))
let int_to_hexchar (i : nativeint) : char =
   match i with
     0n -> '0'
   | 1n -> '1'
   | 2n -> '2'
   | 3n -> '3'
   | 4n -> '4'
   | 5n -> '5'
   | 6n -> '6'
   | 7n -> '7'
   | 8n -> '8'
   | 9n -> '9'
   | 10n -> 'a'
   | 11n -> 'b'
   | 12n -> 'c'
   | 13n -> 'd'
   | 14n -> 'e'
   | 15n -> 'f'
   | _ -> failwith "int_to_hexchar"
let hexchar_to_int (c : char) : nativeint =
   match c with
     '0' -> 0n
   | '1' -> 1n
   | '2' -> 2n
   | '3' -> 3n
   | '4' -> 4n
   | '5' -> 5n
   | '6' -> 6n
   | '7' -> 7n
   | '8' -> 8n
   | '9' -> 9n
   | 'a' -> 10n
   | 'b' -> 11n
   | 'c' -> 12n
   | 'd' -> 13n
   | 'e' -> 14n
   | 'f' -> 15n
   | 'A' -> 10n
   | 'B' -> 11n
   | 'C' -> 12n
   | 'D' -> 13n
   | 'E' -> 14n
   | 'F' -> 15n
   | _ -> failwith "hexchar_to_int"
let merge_nibbles niba nibb =
    let ciba = hexchar_to_int nibb in
    let cibb = hexchar_to_int niba in
    let res = (Nativeint.shift_left cibb 4) in
    let res = (Nativeint.logxor res ciba) in
    let res = Char.chr (Nativeint.to_int res) in
    (res)
let pack hexstr =
     let len = String.length hexstr in
     let half_len = len / 2 in
     let res = String.create half_len in
     let j = ref 0 in
     for i = 0 to len - 2 do
        if (i mod 2 == 0) then
          (
          let tmp = merge_nibbles hexstr.[i] hexstr.[i+1] in
          res.[!j] <- tmp;
          j := !j +1;
          )
     done;
     (res)

let char_array_to_string = fun a -> let s = String.create (Array.length a) in
  Array.iteri (fun i x -> String.set s i x) a; s;;

let string_to_char_array = fun s -> Array.init (String.length s) (fun i -> s.[i]);;

let char_list_to_string = fun a -> let s = String.create (List.length a) in
  List.iteri (fun i x -> String.set s i x) a; s;;

let string_to_char_list = fun s -> Array.to_list (string_to_char_array s);;

let sprint_hex_array myarray =
  let s = Array.fold_left (
    fun a elem -> Printf.sprintf "%s%02x" a (int_of_char elem);
  ) "" myarray in
  (Printf.sprintf "%s" s)

let sprint_hex_string mystring = sprint_hex_array (string_to_char_array mystring)

(* Find the number of bits of a string, i.e. without left zero bits *)
let find_bits_number in_string =
  (* Get the zero bytes *)
  let count = ref 0 in
  let _ = (try
    while !count < (String.length in_string) do
        if in_string.[!count] = (Char.chr 0) then
          count := !count + 1
        else
          raise Exit
    done with Exit -> ()) in
  if !count = String.length in_string then
    (8*(String.length in_string))
  else
    let _ = (count := 8*(!count)) in
    (* Check next byte to get its non zero bits *)
    let i = ref 0 in
    let last_byte = in_string.[!count] in
    let _ = (try
      while !i < 7 do
        if (Char.code last_byte) lsr (7-(!i)) = 0 then
          begin
          count := !count + 1;
          i := !i + 1
          end
        else
          raise Exit
      done with Exit -> ()) in
    ((8*(String.length in_string)) - !count)
