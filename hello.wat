(module
  (type (;0;) (func (param i32) (result i32)))
  (type (;1;) (func (result i32)))
  (type (;2;) (func (param i32 i32) (result i32)))
  (import "env" "__linear_memory" (memory (;0;) 0))
  (import "env" "__indirect_function_table" (table (;0;) 0 funcref))
  (func $example (type 0) (param i32) (result i32)
    local.get 0
    i32.const 3
    i32.add)
  (func $__original_main (type 1) (result i32)
    i32.const 8
    call $example)
  (func $main (type 2) (param i32 i32) (result i32)
    call $__original_main))
