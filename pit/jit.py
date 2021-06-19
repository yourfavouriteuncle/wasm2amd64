#!/usr/bin/env python3

import os
import ctypes
import sys
import memory
import logging
import numpy as np

from assembler import Assembler
from compiler import wasm_compiler, disassemble
from optimizer import peephole


logging.basicConfig(
    stream=sys.stdout,
    format='%(levelname)s: %(message)s',
    level=logging.DEBUG,
)
log = logging.getLogger(__name__)


def print_ir(ir):
    for instruction in ir:
        op, args = instruction[0], instruction[1:]
        args = filter(lambda x: x is not None, args)
        log.info("  %-6s %s" % (op, ", ".join(map(str, args))))


def to_native(bytecode):
    log.info("---")
    log.info("ir:")
    ir = wasm_compiler(bytecode)

    print_ir(ir)

    log.info("---")
    log.info("optimizations:")

    while True:
        optimized = list(peephole(ir))
        reduction = len(ir) - len(optimized)
        ir = optimized
        log.info("removed %d instructions" % reduction)

        if not reduction:
            break

    log.info("---")
    log.info("ir:")
    print_ir(ir)

    # Compile to native code
    asm = Assembler(memory.PAGESIZE)
    for name, a, b in ir:
        emit = getattr(asm, name)
        emit(a, b)

    # Make block executable and read-only
    memory.make_executable(asm.block, asm.size)

    argcount = 1

    if argcount:
        # Assume all arguments are 64-bit
        signature = ctypes.CFUNCTYPE(*([ctypes.c_uint64] * argcount))
    else:
        signature = ctypes.CFUNCTYPE(None)

    signature.restype = ctypes.c_uint64
    native = signature(asm.address) 
    native.raw = asm.raw
    native.address = asm.address

    return native, asm

def jit(ast):
    native, asm = to_native(ast)

    log.info('---')
    result = disassemble(native)
    log.info('disassembly:\n' + result)
    log.info('---')

    log.info(f'execution starting')
    result = native(6)
    log.info(f'execution finished: {result}')

    log.info('---')
    log.info('cleaning memory up')
    memory.destroy_block(asm.block, memory.PAGESIZE)
    del asm.block
    del native


if __name__ == '__main__':
    usage = """Invalid call.

USAGE: python jit.py file.wasm
    """

    if len(sys.argv) != 2:
        log.error(usage)
        sys.exit(-1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        log.error('invalid file path')
        sys.exit(-1)

    with open(file_path, 'rb') as w:
        data = w.read()
        array = np.array([
            data[i:i + 1] 
            for i in range(0, len(data), 1)
        ], dtype=bytes)
        jit(array)
