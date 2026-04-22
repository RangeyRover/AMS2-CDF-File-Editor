import re
with open('cdf_editorV0.2.py', 'r', encoding='utf-8') as f:
    text = f.read()

match = re.search(r'(CDF_DEFS: List\[CdfFieldDef\] = \[.*?\]\n)', text, re.DOTALL)
if match:
    header = """from typing import List, Tuple, Literal
from dataclasses import dataclass
Scalar = Literal["byte", "float", "int32", "uint32"]

@dataclass(frozen=True)
class CdfFieldDef:
    name: str
    section: str
    marker: bytes
    layout: Tuple[Scalar, ...]
    notes: str = ""
    optional: bool = True
    repeatable: bool = True

def hx(s: str) -> bytes:
    return bytes.fromhex(s)

"""
    with open('cdf_defs_legacy.py', 'w', encoding='utf-8') as f2:
        f2.write(header + match.group(1))
    print("Extracted CDF_DEFS to cdf_defs_legacy.py")
else:
    print("Could not find CDF_DEFS block")
