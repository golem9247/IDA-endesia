import re

def ishex(v):
    v = v.lower()
    if "0x" in v or v.endswith("h"):
        return True
    for kk in ["a","b","c","d","e","f"]:
        if kk in v:
            return True
    return False

def cast_from_str(v):
    return int(v,16) if ishex(v) else int(v,10)

def phex(value, pad=8):
    return f"{value:#0{pad}x}"

def pad(value, pad=64, fill=" "):
    return value + (pad-len(value))*fill 

def instr_match_op_cst(instructions, ops, cst):
    if len(instructions) == 0:
        return 0
    
    for ea, disasm in instructions:
        for operation in ops:
            disasm = disasm.lower()
            if not operation in disasm:
                continue

            # Our main parsing is regex
            # this is pretty horrible but work
            match = re.search("\s+\w+,\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+h|\d+|#0x[0-9a-fA-F]+)", disasm, re.IGNORECASE)
            if not match:
                continue
            match_gr = match.group(1).replace("h","").replace("#","")
            instr_const = cast_from_str(match_gr)
            if instr_const == cst:
                return ea

    return 0