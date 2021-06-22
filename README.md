# wasm2amd64

A JIT for a subset of WebAssembly to x86_64.

To run go to the `./pit` folder and run `python jit.py wasm/arithmetic.wasm`.

It works by parsin the binary format of the WebAssembly file and translating it directly to native x86_64 instructions.

  - It supports addition, subtraction and multiplication
  - It parses the Global, Export, Type, Function, and Code sections
  - It doesn't support function calling
