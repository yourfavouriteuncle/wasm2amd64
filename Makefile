all:
	emcc main.c -s WASM=1 -Oz -c -o hello.wasm
	wasm2wat hello.wasm > hello.wat

