def optimize(ir):
    """Performs peephole optimizations on the IR."""
    def fetch(n):
        if n < len(ir):
            return ir[n]
        else:
            return None, None, None

    index = 0
    while index < len(ir):
        op1, a1, b1 = fetch(index)
        op2, a2, b2 = fetch(index + 1)
        op3, a3, b3 = fetch(index + 2)
        op4, a4, b4 = fetch(index + 3)

        # Remove nonsensical moves
        if op1 == "mov" and a1 == b1:
            index += 1
            continue

        # Translate
        #    mov rsi, rax
        #    mov rbx, rsi
        # to mov rbx, rax
        if op1 == op2 == "mov" and a1 == b2:
            index += 2
            yield "mov", a2, b1
            continue

        # Short-circuit push x/pop y
        if op1 == "push" and op2 == "pop":
            index += 2
            yield "mov", a2, a1
            continue

        # Same as above, but with an in-between instruction
        if op1 == "push" and op3 == "pop" and op2 not in ("push", "pop"):
            # Only do this if a3 is not modified in the middle instruction. An
            # obvious improvement would be to allow an arbitrary number of
            # in-between instructions.
            if a2 != a3:
                index += 3
                yield "mov", a3, a1
                yield op2, a2, b2
                continue

        # Same as above, but with one in-between instruction.
        # TODO: Generalize this, then remove the previous two
        if (
            op1 == "push" and 
            op4 == "pop" and
            op2 not in ("push", "pop") and
            op3 not in ("push", "pop")
        ):
            if a2 != a4 and a3 != a4:
                index += 4
                yield "mov", a4, a1
                yield op2, a2, b2
                yield op3, a3, b3
                continue

        index += 1
        yield op1, a1, b1


def print_ir(ir):
    for instruction in ir:
        op, args = instruction[0], instruction[1:]
        args = filter(lambda x: x is not None, args)
        log.info("  %-6s %s" % (op, ", ".join(map(str, args))))
