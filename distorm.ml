(* distorm3.ml                                                           *)
(* Copyright (C) 2013 Carl Pulley <c.j.pulley@hud.ac.uk>                   *)
(*                                                                         *)
(* This program is free software; you can redistribute it and/or modify    *)
(* it under the terms of the GNU General Public License as published by    *)
(* the Free Software Foundation; either version 2 of the License, or (at   *)
(* your option) any later version.                                         *)
(*                                                                         *)
(* This program is distributed in the hope that it will be useful, but     *)
(* WITHOUT ANY WARRANTY; without even the implied warranty of              *)
(* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU        *)
(* General Public License for more details.                                *)
(*                                                                         *)
(* You should have received a copy of the GNU General Public License       *)
(* along with this program; if not, write to the Free Software             *)
(* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA *)

open Ctypes
open Foreign
open Unsigned

exception DistormException of string

type _DecodeType = Decode16Bits | Decode32Bits | Decode64Bits
let uint8_of_DecodeType = function
| Decode16Bits -> UInt8.of_int 0
| Decode32Bits -> UInt8.of_int 1
| Decode64Bits -> UInt8.of_int 2
let _DecodeType_of_uint8 n =
	match UInt8.to_int n with
	| 0 -> Decode16Bits
  | 1 -> Decode32Bits
  | 2 -> Decode64Bits
  | _ -> raise (DistormException "_DecodeType_of_uint8: unknown uint8 encoding")
let _DecodeType = view ~read:_DecodeType_of_uint8 ~write:uint8_of_DecodeType uint8_t

let max_text_size = 48

type _WString
let struct_WString = structure "struct_WString"
let psize = struct_WString *:* uint
let p     = struct_WString *:* array max_text_size uchar (* p is a null terminated string. *)
let () = seal (struct_WString : _WString structure typ)
let string_of_struct_WString v =
	let size = UInt.to_int(getf v psize) in
    assert(0 <= size && size < max_text_size && Array.get (getf v p) size = UChar.of_int 0);
		String.sub (String.concat "" (List.map (fun x -> String.make 1 (Char.chr(UChar.to_int x))) (Array.to_list(getf v p)))) 0 size
let struct_WString_of_string s =
	let result = make struct_WString in
	let () = setf result psize (UInt.of_int(String.length s)) in
	let () = setf result p (Array.of_list uchar (List.map (fun x -> UChar.of_int(Char.code(String.get x 0))) (Str.split (Str.regexp "") (s ^ "\x00")))) in
		assert(String.length s < max_text_size);
		result
let _WString = view ~read:string_of_struct_WString ~write:struct_WString_of_string struct_WString

type _DecodedInst
let _DecodedInst = structure "_DecodedInst"
let mnemonic       = _DecodedInst *:* _WString (* Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. *)
let operands       = _DecodedInst *:* _WString (* Operands of the decoded instruction, up to 3 operands, comma-seperated. *)
let instructionHex = _DecodedInst *:* _WString (* Hex dump - little endian, including prefixes. *)
let size           = _DecodedInst *:* uint     (* Size of decoded instruction. *)
let offset         = _DecodedInst *:* int      (* Start offset of the decoded instruction. *)
let () = seal (_DecodedInst : _DecodedInst structure typ)

type _DecodeResult = DECRES_NONE | DECRES_SUCCESS | DECRES_MEMORYERR | DECRES_INPUTERR | DECRES_FILTERED
let _DecodeResult_of_uint8 n =
  match UInt8.to_int n with
  | 0 -> DECRES_NONE
  | 1 -> DECRES_SUCCESS
  | 2 -> DECRES_MEMORYERR
  | 3 -> DECRES_INPUTERR
  | 4 -> DECRES_FILTERED
  | _ -> raise (DistormException "_DecodeResult_of_uint8: unknown uint8 encoding")
let uint8_of_DecodeResult = function
  | DECRES_NONE -> UInt8.of_int 0
  | DECRES_SUCCESS -> UInt8.of_int 1
  | DECRES_MEMORYERR -> UInt8.of_int 2
  | DECRES_INPUTERR -> UInt8.of_int 3
  | DECRES_FILTERED -> UInt8.of_int 4
let _DecodeResult = view ~read:_DecodeResult_of_uint8 ~write:uint8_of_DecodeResult uint8_t

let distorm_decode = 
  let distorm3 = Dl.dlopen ~filename:"libdistorm3.so" ~flags:[Dl.RTLD_LAZY] in
    foreign ~from:distorm3 "distorm_decode64" (int @-> string @-> int @-> _DecodeType @-> ptr _DecodedInst @-> uint @-> ptr uint @-> returning _DecodeResult)

let single_disasm arch code = 
  let codeLen = String.length code in
    if codeLen = 0 then
      (DECRES_INPUTERR, 0, "", "", "")
    else
      let to_hex_str c = Printf.sprintf "%X" (Char.code c) in
      let codeOffset = 0 in
      let result = allocate_n _DecodedInst ~count:1 in
      let usedInstructionsCount = allocate uint (UInt.of_int 0) in
        try
          let rcode: _DecodeResult = distorm_decode codeOffset code codeLen arch result (Unsigned.UInt.of_int 1) usedInstructionsCount in
          let raw_ins = getf !@result mnemonic in
          let ins = if raw_ins <> "" then raw_ins else ("DB " ^ (to_hex_str(String.get code 0))) in
          let ops = if raw_ins <> "" then getf !@result operands else "" in
          let hex = if raw_ins <> "" then getf !@result instructionHex else (to_hex_str(String.get code 0)) in
          let sz = if raw_ins <> "" then UInt.to_int(getf !@result size) else 1 in
            (rcode, sz, ins, ops, hex)
        with Assert_failure _ ->
          (* Blindy assume that instruction is invalid and memory hasn't been initialised *)
          (* - hence this assertion failure                                               *)
          (DECRES_INPUTERR, 1, "DB " ^ (to_hex_str(String.get code 0)), "", to_hex_str(String.get code 0))
