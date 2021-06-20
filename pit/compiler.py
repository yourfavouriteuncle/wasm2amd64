import numpy as np
import logging

log = logging.getLogger(__name__)

END = '0b'
LF = '0a'
CR = '0d'
TERM = '0f'
TYPE_SECTION = '01'
FUNC_SECTION = '03'
GLOBAL_SECTION = '06'
EXPORT_SECTION = '07'
CODE_SECTION = '0a'
INT32 = '7f'

# expressions
INT32_ADD = '6a'
INT32_MUL = '6c'
INT32_SUB = '6b'
INT32_DIV_S = '6d'
INT32_CONST = '41'
FUNC_CALL = '10'

MUT_CONST = '' # 00

FUNC_TYPE_MAGIC = '60'

FUNC_ID = '' # 00
GLOB_ID = '03' # 00

LOOKUP = {
    'functions': [],
    'exports': [],
    'globals': [],
    'types': [],
}


def log_lookup():
    log.info('---')
    log.info('Compiler Lookup Table:')
    for (k, v) in LOOKUP.items():
        log.info(k + '\t: ' + str(v))
    log.info('---')


def verify_header(bytes):
    assert bytes[:4].tobytes().hex() == '0061736d'


def verify_version(bytes):
    assert bytes[:4].tobytes().hex() == '01000000'


def verify_end(bytes):
    assert bytes[0].hex() == END


def variable(number):
    # AMD64 argument passing order for our purposes.
    order = ("rdi", "rsi", "rdx", "rcx")
    return order[number]


def register(num):
    order = ('rdi', 'rsi', 'rdx', 'rcx')
    assert num < len(order)
    return order[num]


def parse_int(bytes):
    result = 0
    shift = 0
    index = 0

    size = 32;

    while True:
        byte = int.from_bytes(
            bytes[index],
            byteorder='little',
        )

        result |= (byte & 0x7f) << shift

        if not (byte & 0x80):
            if (
                (shift < 32) and 
                (byte & 0x40)
            ) != 0:
                return result | (~0 << shift), index + 1
            return result, index + 1

        index += 1
        shift += 7


def parse_uint(bytes):
    # https://en.wikipedia.org/wiki/LEB128
    # https://github.com/codenotes/ntcorewithwolfram/blob/master/src/leb128.cpp#L69
    result = 0
    shift = 0
    index = 0

    while True:
        byte = int.from_bytes(
            bytes[index],
            byteorder='little',
        )

        result |= (byte & 0x7f) << shift

        if not (byte & 0x80):
            return result, index + 1

        index += 1
        shift += 7


def parse_section(bytes):
    section_id = bytes[0].hex()
    offset = 1

    if section_id == GLOBAL_SECTION:
        section_parser = parse_global_section
    elif section_id == EXPORT_SECTION:
        section_parser = parse_export_section
    elif section_id == TYPE_SECTION:
        section_parser = parse_type_section
    elif section_id == FUNC_SECTION:
        section_parser = parse_func_section
    elif section_id == CODE_SECTION:
        section_parser = parse_code_section
    else:
        raise NotImplementedError('unknown section')

    asm, read = section_parser(bytes[offset:])
    offset += read

    return asm, offset


def parse_expression(bytes, values):
    offset = 0

    expr_type = bytes[offset].hex()
    offset += 1

    if expr_type == FUNC_CALL:
        raise NotImplementedError('no func call')

    elif expr_type == INT32_CONST:
        value, read = parse_int(bytes[offset:])
        offset += read
        asm = []
        asm.append(['immediate', 'rax', value])
        asm.append(['push', 'rax', None])

        return asm, offset
    elif expr_type == INT32_MUL:
        asm = []
        asm.append(['pop', 'rax', None])
        asm.append(['pop', 'rbx', None])
        asm.append(['imul', 'rax', 'rbx'])
        asm.append(['push', 'rax', None])

        return asm, offset

    elif expr_type == INT32_SUB:
        asm = []
        asm.append(['pop', 'rbx', None])
        asm.append(['pop', 'rax', None])
        asm.append(['sub', 'rax', 'rbx'])
        asm.append(['push', 'rax', None])

        return asm, offset

    elif expr_type == INT32_ADD:
        asm = []
        asm.append(['pop', 'rax', None])
        asm.append(['pop', 'rbx', None])
        asm.append(['add', 'rax', 'rbx'])
        asm.append(['push', 'rax', None])

        return asm, offset

    else:
        raise NotImplementedError('unknown expr')


def parse_code(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    loclen, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []
    values = []

    for _ in range(loclen):
        value, read = parse_val_type(bytes[offset:])
        offset += read
        values.append(value)

    while bytes[offset].hex() != END:
        ir, read = parse_expression(bytes[offset:], values)
        offset += read
        asm.extend(ir)

    offset += 1

    return asm, offset


def parse_code_section(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    len, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []

    for _ in range(len):
        code, read = parse_code(bytes[offset:])
        offset += read
        asm.extend(code)
        
    return asm, offset


def parse_func_section(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    len, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []

    for _ in range(len):
        type_id, read = parse_uint(bytes[offset:])
        LOOKUP['functions'].append(type_id)
        offset += read

    return asm, offset


def parse_val_type(bytes):
    numtype = bytes[0].hex()
    assert numtype == INT32

    return numtype, 1


def parse_result_type(bytes):
    offset = 0

    len, o1 = parse_uint(bytes[offset:])
    offset += o1

    res = []

    for _ in range(len):
        valtype, read = parse_val_type(bytes[offset:])
        res.append(valtype)
        offset += read

    return res, offset


def parse_func_type(bytes):
    offset = 0

    magic = bytes[offset].hex()
    assert magic == FUNC_TYPE_MAGIC
    offset += 1

    args, o2 = parse_result_type(bytes[offset:])
    offset += o2

    res, o3 = parse_result_type(bytes[offset:])
    offset += o3

    return [args, res], offset


def parse_type_section(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    len, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []

    for _ in range(len):
        sig, read = parse_func_type(bytes[offset:])
        LOOKUP['types'].append(sig)
        offset += read

    return asm, offset


def parse_export(bytes):
    offset = 0

    name, o1 = parse_name(bytes)
    offset += o1

    desc = bytes[offset].hex()
    offset += 1

    if desc == FUNC_ID:
        desc = 'FUNCTIONS'
    elif desc == GLOB_ID:
        desc = 'GLOBALS'
    else:
        raise NotImplementedError('export desc')

    ref, o2 = parse_uint(bytes[offset:])
    offset += o2

    return (name.decode(), desc, str(ref)), offset


def parse_export_section(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    len, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []

    for _ in range(len):
        # don't need the export right now
        (name, desc, ref), read = parse_export(bytes[offset:])
        LOOKUP['exports'].append([name, desc, ref])
        offset += read

    return asm, offset


def parse_global_section(bytes):
    offset = 0

    size, o1 = parse_uint(bytes[offset:])
    offset += o1

    len, o2 = parse_uint(bytes[offset:])
    offset += o2

    asm = []

    for i in range(len):
        value, read = parse_global(bytes[offset:])
        LOOKUP['globals'].append(value)
        offset += read

    return asm, offset


def parse_numeric_op(bytes):
    return False


def parse_name(bytes):
    offset = 0

    len, o1 = parse_uint(bytes)
    offset += o1

    return bytes[offset:offset + len].tostring(), offset + len


def parse_global(bytes):
    # type
    if bytes[0].hex() != INT32:
        raise NotImplementedError('glob int32')

    # mutability
    if bytes[1].hex() != MUT_CONST:
        raise NotImplementedError('glob mut const')

    # initializer
    if bytes[2].hex() != INT32_CONST:
        raise NotImplementedError('glob init const')

    value, read = parse_int(bytes[3:])

    offset = read + 3
    verify_end(bytes[offset:])

    return hex(value), offset + 1


def wasm_compiler(bytecode):
    verify_header(bytecode)
    verify_version(bytecode[4:])

    # slice off header and version
    data = bytecode[8:]

    ir = []

    while len(data):
        if res := parse_section(data):

            # don't append empty list
            if res[0]:
                for instr in res[0]:
                    ir.append(instr)

            data = data[res[1]:]
            continue

        if len(data) == 1 and data[0].hex() == LF:
            break

    # add ret at the end of execution
    ir.append(['pop', 'rax', None])
    ir.append(['ret', None, None])
    log_lookup()

    return ir


def disassemble(function):
    """Decompile x86_64 block"""

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
