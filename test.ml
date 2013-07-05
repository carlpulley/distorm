open OUnit
open Unsigned

let test_inc_disasm4 () =
  let rcode, size, mneumonic, operands, hex = Distorm.single_disasm Distorm.Decode32Bits "AAAA" in
    assert_equal rcode Distorm.DECRES_MEMORYERR;
    assert_equal size 1;
    assert_equal mneumonic "INC";
    assert_equal operands "ECX";
    assert_equal hex "41"

let test_inc_disasm1 () =
  let rcode, size, mneumonic, operands, hex = Distorm.single_disasm Distorm.Decode32Bits "A" in
    assert_equal rcode Distorm.DECRES_SUCCESS;
    assert_equal size 1;
    assert_equal mneumonic "INC";
    assert_equal operands "ECX";
    assert_equal hex "41"

let suite = "OUnit Distorm tests" >::: [
  "test_inc_disasm1" >:: test_inc_disasm1;
  "test_inc_disasm4" >:: test_inc_disasm4
]

let _ =
  run_test_tt_main suite
