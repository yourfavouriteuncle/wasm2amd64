import memory
import ctypes


class Assembler():
    """An amd64 assembler."""

    def __init__(self, size):
        self.block = memory.create_block(size)
        self.index = 0
        self.size = size
        self.constants = {}

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

    def section(self, name, values):
        self.constants[name] = values
