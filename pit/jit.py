#!/usr/bin/env python3

import os
import ctypes
import sys
import memory
import logging
import numpy as np

from compiler import wasm_compiler
from optimizer import optimize


logging.basicConfig(
    stream=sys.stdout,
    format='%(levelname)s: %(message)s',
    level=logging.DEBUG,
)
log = logging.getLogger(__name__)


class Assembler():
    """An amd64 assembler."""

    def __init__(self, size):
        self.block = memory.create_block(size)
        self.index = 0
        self.size = size

    @property
    def raw(self):
        """Returns machine code as a raw string."""
        return bytes(self.block[:self.index])

    @property
    def address(self):
        """Returns address of block in memory."""
        return ctypes.cast(self.block, ctypes.c_void_p).value

    def little_endian(self, n):
        """Converts 64-bit number to little-endian format."""
        if n is None:
            n = 0
        return [(n & (0xff << (i*8))) >> (i*8) for i in range(8)]

    def registers(self, a, b=None):
        """Encodes one or two registers for machine code instructions."""
        order = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
        enc = order.index(a)
        if b is not None:
            enc = enc << 3 | order.index(b)
        return enc

    def emit(self, *args):
        """Writes machine code to memory block."""
        for code in args:
            self.block[self.index] = code
            self.index += 1

    def ret(self, a, b):
        self.emit(0xc3)

    def push(self, a, _):
        self.emit(0x50 | self.registers(a))

    def pop(self, a, _):
        self.emit(0x58 | self.registers(a))

    def imul(self, a, b):
        self.emit(0x48, 0x0f, 0xaf, 0xc0 | self.registers(a, b))

    def add(self, a, b):
        self.emit(0x48, 0x01, 0xc0 | self.registers(b, a))

    def sub(self, a, b):
        self.emit(0x48, 0x29, 0xc0 | self.registers(b, a))

    def neg(self, a, _):
        self.emit(0x48, 0xf7, 0xd8 | self.registers(a))

    def mov(self, a, b):
        self.emit(0x48, 0x89, 0xc0 | self.registers(b, a))

    def immediate(self, a, number):
        self.emit(0x48, 0xb8 | self.registers(a), *self.little_endian(number))


def to_native(bytecode):
    ir = wasm_compiler(bytecode)
    ir = list(ir)

    print_ir(ir)

    log.info("---")
    log.info("Optimization:")

    while True:
        optimized = list(optimize(ir))
        reduction = len(ir) - len(optimized)
        ir = optimized
        log.info("removed %d instructions" % reduction)

        if not reduction:
            break

    log.info("---")
    print_ir(ir)

    # Compile to native code
    asm = Assembler(memory.PAGESIZE)
    for name, a, b in ir:
        emit = getattr(asm, name)
        emit(a, b)

    # populate block with multiplier code
    # memory.make_multiplier(asm.block, 5)

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

    log.info('execution started')
    result = disassemble(native)
    log.info(f'disassembled: {result}')
    log.info(f'execution starting')
    result = native(6)
    log.info(f'execution finished: {result}')

    log.info('---')
    log.info('cleaning memory up')
    memory.destroy_block(asm.block, memory.PAGESIZE)
    del asm.block
    del native


def disassemble(function):
    """Returns disassembly string of natively compiled function."""

    def hexbytes(raw):
        return "".join("%02x " % b for b in raw)

    import capstone

    out = ""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    for i in md.disasm(function.raw, function.address):
        out += "0x%x %-15s%s %s\n" % (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str)
        if i.mnemonic == "ret":
            break

    return out


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
