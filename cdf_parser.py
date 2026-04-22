import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple
import sys
import os

Scalar = Literal["byte", "int16", "float", "int32", "uint32"]

@dataclass(frozen=True)
class CdfFieldDef:
    name: str
    section: str
    group: str
    marker: bytes
    layout: Tuple[Scalar, ...]
    notes: str = ""
    optional: bool = True
    repeatable: bool = True

@dataclass
class CdfFieldInstance:
    definition: CdfFieldDef
    occurrence: int
    offset_marker: int
    offset_value: int
    raw_value_bytes: bytes
    value: Tuple[Any, ...]

_FMT: Dict[Scalar, Tuple[str, int]] = {
    "byte":   ("<B", 1),
    "int16":  ("<h", 2),
    "float":  ("<f", 4),
    "int32":  ("<i", 4),
    "uint32": ("<I", 4),
}

def load_dictionary(xml_path: Optional[str] = None) -> List[CdfFieldDef]:
    """Load XML dictionary dynamically into CdfFieldDef structures."""
    
    tree = None
    
    if not xml_path:
        # Try to use the precompiled python string dictionary (bulletproof for PyInstaller)
        try:
            from default_dictionary import XML_CONTENT
            if XML_CONTENT:
                tree = ET.ElementTree(ET.fromstring(XML_CONTENT))
        except ImportError:
            pass
        
        # Fallback to local files if it wasn't compiled in
        if tree is None:
            base_dir = os.path.abspath(os.path.dirname(__file__))
            xml_path = os.path.join(base_dir, 'cdf-hex-map.xml')
            if not os.path.exists(xml_path):
                # Check one directory up if run from tests/
                parent_xml = os.path.abspath(os.path.join(base_dir, '..', 'cdf-hex-map.xml'))
                if os.path.exists(parent_xml):
                    xml_path = parent_xml

    if tree is None:
        tree = ET.parse(xml_path)
        
    root = tree.getroot()
    
    defs: List[CdfFieldDef] = []
    
    # Iterate through <section> -> <group> -> <block>
    for sec_el in root.findall('.//section'):
        sec_name = sec_el.attrib.get('name', 'UNKNOWN_SECTION')
        for grp_el in sec_el.findall('.//group'):
            grp_name = grp_el.attrib.get('name', 'UNKNOWN_GROUP')
            for blk_el in grp_el.findall('.//block'):
                blk_name = blk_el.attrib.get('name', 'UNKNOWN_BLOCK')
                signature = blk_el.attrib.get('signature', '')
                marker = bytes.fromhex(signature)
                
                # Notes
                notes_el = blk_el.find('notes')
                notes = notes_el.text.strip() if notes_el is not None and notes_el.text else ""
                
                # Append Value Range and Rationale
                vr_el = blk_el.find('value_range')
                if vr_el is not None and vr_el.text and vr_el.text.strip():
                    notes += f"\nValue Range: {vr_el.text.strip()}"
                
                rat_el = blk_el.find('rationale')
                if rat_el is not None and rat_el.text and rat_el.text.strip():
                    notes += f"\nRationale: {rat_el.text.strip()}"
                    
                notes = notes.strip()
                
                # Layout
                layout = []
                for field_el in blk_el.findall('field'):
                    layout.append(field_el.attrib.get('type'))
                
                defs.append(CdfFieldDef(
                    name=blk_name,
                    section=sec_name,
                    group=grp_name,
                    marker=marker,
                    layout=tuple(layout),
                    notes=notes
                ))
    
    return defs

def find_all(haystack: bytes, needle: bytes) -> List[int]:
    out: List[int] = []
    i = 0
    while True:
        j = haystack.find(needle, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1

def decode_payload(layout: Tuple[Scalar, ...], data: bytes, off: int) -> Tuple[Tuple[Any, ...], int, bytes]:
    vals: List[Any] = []
    start = off
    for t in layout:
        fmt, n = _FMT[t]
        chunk = data[off:off+n]
        if len(chunk) != n:
            raise ValueError(f"EOF decoding {t} at {off:#x}")
        vals.append(struct.unpack(fmt, chunk)[0])
        off += n
    return tuple(vals), off, data[start:off]

def encode_payload(layout: Tuple[Scalar, ...], values: Tuple[Any, ...]) -> bytes:
    if len(values) != len(layout):
        raise ValueError(f"Value arity mismatch (expected {len(layout)} got {len(values)})")
    out = bytearray()
    for t, v in zip(layout, values):
        fmt, _n = _FMT[t]
        if t == "float":
            v = float(v)
        else:
            v = int(v)
        out += struct.pack(fmt, v)
    return bytes(out)

def parse_cdfbin(blob: bytes, defs: List[CdfFieldDef]) -> List[CdfFieldInstance]:
    instances: List[CdfFieldInstance] = []
    occ_map: Dict[Tuple[str, str, str], int] = {}
    for d in defs:
        positions = find_all(blob, d.marker)
        if not positions:
            continue

        key = (d.section, d.name, d.marker.hex(" "))
        for pos in positions:
            occ = occ_map.get(key, 0)
            occ_map[key] = occ + 1

            val_off = pos + len(d.marker)
            # Some signatures might be just markers with no layout
            try:
                value, _end, raw = decode_payload(d.layout, blob, val_off)
                instances.append(CdfFieldInstance(
                    definition=d,
                    occurrence=occ,
                    offset_marker=pos,
                    offset_value=val_off,
                    raw_value_bytes=raw,
                    value=value
                ))
            except Exception as e:
                # If we hit EOF or decoding fails, we skip this occurrence
                pass

    instances.sort(key=lambda i: (i.definition.section, i.definition.name, i.occurrence))
    return instances

def read_u32le(blob: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(blob):
        raise ValueError(f"read_u32le out of bounds at {off:#x}")
    return struct.unpack_from("<I", blob, off)[0]

def write_u32le(buf: bytearray, off: int, v: int) -> None:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"write_u32le out of bounds at {off:#x}")
    struct.pack_into("<I", buf, off, int(v) & 0xFFFFFFFF)

@dataclass
class ByteCountCheckResult:
    ok: bool
    problems: List[str]
    regs: Dict[str, int]
    suggested: Optional[Dict[str, int]]

def check_byte_count_registers(blob: bytes) -> ByteCountCheckResult:
    file_len = len(blob)
    R0 = read_u32le(blob, 0x0008)
    R1 = read_u32le(blob, 0x0014)
    R2 = read_u32le(blob, 0x0020)
    R3 = read_u32le(blob, 0x0024)

    regs = {"R0_file_len": R0, "R1_mid_len": R1, "R2_end_len": R2, "R3_end_start": R3}
    problems: List[str] = []

    if R3 > file_len:
        problems.append(f"R3 (end start) out of range: {R3} > file_len {file_len}")
    if R2 > file_len:
        problems.append(f"R2 (end len) out of range: {R2} > file_len {file_len}")

    if R3 <= file_len and R2 <= file_len:
        if R3 + R2 != file_len:
            problems.append(f"End geometry mismatch: R3+R2={R3+R2} != file_len {file_len}")

    if R0 != file_len:
        problems.append(f"R0 mismatch: R0={R0} != file_len {file_len}")

    if R3 >= 0x0028:
        exp_R1 = R3 - 0x0028
        if R1 != exp_R1:
            problems.append(f"R1 mismatch: R1={R1} != (R3-0x0028)={exp_R1}")
    else:
        problems.append(f"R3 < 0x0028 (unexpected): R3={R3}")

    ok = (len(problems) == 0)
    suggested: Optional[Dict[str, int]] = None
    if not ok:
        file_len = len(blob)
        end_start = None
        end_len = None

        if R3 <= file_len and R2 <= file_len and (R3 + R2 == file_len):
            end_start, end_len = R3, R2
        else:
            if 0 < R2 <= file_len:
                end_start, end_len = file_len - R2, R2
            elif 0 < R3 <= file_len:
                end_start, end_len = R3, file_len - R3

        if end_start is not None and end_len is not None:
            suggested = {
                "R0_file_len": file_len,
                "R3_end_start": end_start,
                "R2_end_len": end_len,
                "R1_mid_len": max(0, end_start - 0x0028),
            }

    return ByteCountCheckResult(ok=ok, problems=problems, regs=regs, suggested=suggested)

def apply_byte_count_fix(blob: bytes, suggested: Dict[str, int]) -> bytes:
    out = bytearray(blob)
    write_u32le(out, 0x0008, suggested["R0_file_len"])
    write_u32le(out, 0x0014, suggested["R1_mid_len"])
    write_u32le(out, 0x0020, suggested["R2_end_len"])
    write_u32le(out, 0x0024, suggested["R3_end_start"])
    return bytes(out)
