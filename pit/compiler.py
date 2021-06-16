import numpy as np

END = '0b'
LF = '0a'
CR = '0d'
TERM = '0f'


def parse_header(bytes):
    if bytes[:4].tostring().hex() != '0061736d':
        raise ValueError('invalid header')

    return bytes[4:]


def parse_version(bytes):
    if bytes[:4].tostring().hex() != '01000000':
        raise ValueError('invalid header')

    return bytes[4:]


def variable(number):
    # AMD64 argument passing order for our purposes.
    order = ("rdi", "rsi", "rdx", "rcx")
    return order[number]


def parse_int(bytes):
    return True
    # slice off the byte (i32)
    # return the value
    #
    # ---
    # result = 0;
    # shift = 0;

    # /* the size in bits of the result variable, e.g., 64 if result's type is int64_t */
    # size = number of bits in signed integer;

    # do {
    #   byte = next byte in input;
    #   result |= (low-order 7 bits of byte << shift);
    #   shift += 7;
    # } while (high-order bit of byte != 0);

    # /* sign bit of byte is second high-order bit (0x40) */
    # if ((shift <size) && (sign bit of byte is set))
    # /* sign extend */
    #   result |= (~0 << shift);
    # ---
    return (bytes[1], bytes[:2])


def parse_uint(bytes):
    # result = 0;
    # shift = 0;
    # while (true) {
    # byte = next byte in input;
    # result |= (low-order 7 bits of byte) << shift;
    # if (high-order bit of byte == 0)
    #     break;
    # shift += 7;
    # }
    return True


def parse_byte(bytes):
    return False


def parse_section(bytes):
    return False


def parse_numeric_op(bytes):
    return False


def parse_name(bytes):
    size = parse_uint(bytes)
    content = parse_uint(bytes)


def parse_vector(bytes, datatype):
    if datatype == 'i32':
        size = parse_int(bytes)
        content = parse_int(bytes)
        return (size, content)
    elif datatype == 'byte':
        size = parse_byte(bytes)
        content = parse_byte(bytes)
        return (size, content)
    else:
        raise NotImplementedError()


def wasm_compiler(bytecode):
    headerless = parse_header(bytecode)
    data = parse_version(headerless)

    while data != None:
        print(data)
        break


#def decode(byte):
#    opname = dis.opname[byte]
#
#    if opname.startswith(("UNARY", "BINARY", "INPLACE", "RETURN")):
#        argument = None
#        self.fetch()
#    else:
#        argument = self.fetch()
#
#    return opname, argument

#while self.index < len(self.bytecode):
#    op, arg = self.decode()

#    if op == "LOAD_FAST":
#        yield "push", self.variable(arg), None

#    elif op == "STORE_FAST":
#        yield "pop", "rax", None
#        yield "mov", self.variable(arg), "rax"

#    elif op == "LOAD_CONST":
#        value = self.constants[arg]
#        if value is None:
#            value = 0
#        yield "immediate", "rax", value
#        yield "push", "rax", None

#    elif op == "BINARY_MULTIPLY":
#        yield "pop", "rax", None
#        yield "pop", "rbx", None
#        yield "imul", "rax", "rbx"
#        yield "push", "rax", None

#    elif op in ("BINARY_ADD", "INPLACE_ADD"):
#        yield "pop", "rax", None
#        yield "pop", "rbx", None
#        yield "add", "rax", "rbx"
#        yield "push", "rax", None

#    elif op in ("BINARY_SUBTRACT", "INPLACE_SUBTRACT"):
#        yield "pop", "rbx", None
#        yield "pop", "rax", None
#        yield "sub", "rax", "rbx"
#        yield "push", "rax", None

#    elif op == "UNARY_NEGATIVE":
#        yield "pop", "rax", None
#        yield "neg", "rax", None
#        yield "push", "rax", None

#    elif op == "RETURN_VALUE":
#        yield "pop", "rax", None
#        yield "ret", None, None
#    else:
#        raise NotImplementedError(op)

