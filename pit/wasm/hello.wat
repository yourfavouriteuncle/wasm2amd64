(module
  (type (;0;) (func (result i32)))
  (type (;1;) (func (param i32 i32) (result i32)))
  (func $__original_main (type 0) (result i32)
    i32.const 8)
  (func $main (type 1) (param i32 i32) (result i32)
    call $__original_main))
