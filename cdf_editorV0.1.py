# cdf_editor.py
# Drop-in starter: CDFbin (Project CARS) definition-driven editor + Hex Viewer/Editor
# In-place edits only (payload size must not change).

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

Scalar = Literal["byte", "float", "int32", "uint32"]

try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 1 for system DPI awareness, or 2 for per-monitor DPI awareness.
except Exception:
    pass



# -----------------------------
# Data model
# -----------------------------
@dataclass(frozen=True)
class CdfFieldDef:
    name: str
    section: str
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


# -----------------------------
# Binary helpers
# -----------------------------
_FMT: Dict[Scalar, Tuple[str, int]] = {
    "byte":   ("<B", 1),
    "float":  ("<f", 4),
    "int32":  ("<i", 4),
    "uint32": ("<I", 4),
}

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
            value, _end, raw = decode_payload(d.layout, blob, val_off)
            instances.append(CdfFieldInstance(
                definition=d,
                occurrence=occ,
                offset_marker=pos,
                offset_value=val_off,
                raw_value_bytes=raw,
                value=value
            ))

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
    suggested: Optional[Dict[str, int]]  # new values for R0,R1,R2,R3 (if fixable)

def check_byte_count_registers(blob: bytes) -> ByteCountCheckResult:
    file_len = len(blob)
    R0 = read_u32le(blob, 0x0008)
    R1 = read_u32le(blob, 0x0014)
    R2 = read_u32le(blob, 0x0020)
    R3 = read_u32le(blob, 0x0024)

    regs = {"R0_file_len": R0, "R1_mid_len": R1, "R2_end_len": R2, "R3_end_start": R3}

    problems: List[str] = []

    # basic sanity
    if R3 > file_len:
        problems.append(f"R3 (end start) out of range: {R3} > file_len {file_len}")
    if R2 > file_len:
        problems.append(f"R2 (end len) out of range: {R2} > file_len {file_len}")

    # consistency checks (only if sane enough to evaluate)
    if R3 <= file_len and R2 <= file_len:
        if R3 + R2 != file_len:
            problems.append(f"End geometry mismatch: R3+R2={R3+R2} != file_len {file_len}")

    if R0 != file_len:
        problems.append(f"R0 mismatch: R0={R0} != file_len {file_len}")

    # R1 expected
    if R3 >= 0x0028:
        exp_R1 = R3 - 0x0028
        if R1 != exp_R1:
            problems.append(f"R1 mismatch: R1={R1} != (R3-0x0028)={exp_R1}")
    else:
        problems.append(f"R3 < 0x0028 (unexpected): R3={R3}")

    ok = (len(problems) == 0)

    # Suggest a fix (conservative)
    suggested: Optional[Dict[str, int]] = None
    if not ok:
        file_len = len(blob)

        end_start = None
        end_len = None

        # Case A: trust R3 and R2 if they are coherent
        if R3 <= file_len and R2 <= file_len and (R3 + R2 == file_len):
            end_start, end_len = R3, R2
        else:
            # Case B: infer start from end_len if plausible
            if 0 < R2 <= file_len:
                end_start, end_len = file_len - R2, R2
            # Case C: infer end_len from start if plausible
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


# -----------------------------
# CDF definitions (STARTER SET)
# -----------------------------
def hx(s: str) -> bytes:
    return bytes.fromhex(s)

CDF_DEFS: List[CdfFieldDef] = [
    # =========================
    # GENERAL
    # =========================
    CdfFieldDef("GarageDisplayFlags",      "GENERAL", hx("20 9A 30 40 34"), ("byte",),                 "GarageDisplayFlags={byte}"),
    CdfFieldDef("FeelerFlags",             "GENERAL", hx("20 96 5B FF BF"), ("byte",),                 "FeelerFlags={byte}"),
    CdfFieldDef("Mass",                    "GENERAL", hx("22 67 0B 57 AB"), ("float",),                "Mass={float}"),
    CdfFieldDef("Inertia",                 "GENERAL", hx("24 BB B3 9F 0B A3 02"), ("float","float","float"), "Inertia=(f,f,f)"),
    CdfFieldDef("FuelTankPos",             "GENERAL", hx("24 A0 53 0C 50 83 02"), ("byte","float","float"),  "FuelTankPos=(byte,f,f)"),
    CdfFieldDef("FuelTankMotion",          "GENERAL", hx("24 6F 70 F3 C7 A2"), ("float","float"),       "FuelTankMotion=(f,f)"),

    CdfFieldDef("CDF_UNKN_001",            "GENERAL", hx("26 3A 17 96 C2"), ("byte",),                 "CDF_UNKN_001={byte}"),

    CdfFieldDef("Symmetric",               "GENERAL", hx("20 38 05 5C 3C"), ("byte",),                 "Symmetric={byte}"),
    CdfFieldDef("CGHeight",                "GENERAL", hx("22 18 24 EA A8"), ("float",),                "CGHeight={float}"),

    CdfFieldDef("CGRightRange",            "GENERAL", hx("24 DF 8D 93 CF 23 00"), ("float","byte","byte"), "CGRightRange=(f,b,b)"),
    CdfFieldDef("CGRightSetting",          "GENERAL", hx("28 00 9D 8A CF"), (),                        "CGRightSetting=default"),

    CdfFieldDef("CGRearRange",             "GENERAL", hx("24 BE BA 67 7B 23 00"), ("float","byte","byte"), "CGRearRange=(f,b,b)"),
    CdfFieldDef("CGRearSetting",           "GENERAL", hx("28 D4 4C 53 C4"), (),                        "CGRearSetting=default"),

    CdfFieldDef("Unkn_0x221E5C8F56",       "GENERAL", hx("22 1E 5C 8F 56"), ("float",),                "Unkn_0x221E5C8F56={float}"),
    CdfFieldDef("GraphicalOffset",         "GENERAL", hx("24 86 9A 77 97 03 00"), ("byte","byte","byte"), "GraphicalOffset=(b,b,b)"),
    CdfFieldDef("CollisionOffset",         "GENERAL", hx("24 D2 CF F4 3D 03 00"), ("byte","byte","byte"), "CollisionOffset=(b,b,b)"),

    CdfFieldDef("UndertrayZeroZero",       "GENERAL", hx("24 E9 DE D9 99 23 02"), ("float","byte","float"), "UndertrayZeroZero=(f,b,f)"),
    CdfFieldDef("UndertrayZeroOne",        "GENERAL", hx("24 BA 61 42 62 23 02"), ("float","byte","float"), "UndertrayZeroOne=(f,b,f)"),
    CdfFieldDef("UndertrayZeroTwo",        "GENERAL", hx("24 AC 8D E9 39 23 02"), ("float","byte","float"), "UndertrayZeroTwo=(f,b,f)"),
    CdfFieldDef("UndertrayZeroThree",      "GENERAL", hx("24 C7 C2 3D 06 23 02"), ("float","byte","float"), "UndertrayZeroThree=(f,b,f)"),

    # note: 53 02 isn't in your suffix legend; using the stated payload types from the paste
    CdfFieldDef("UndertrayParams",         "GENERAL", hx("24 86 AE 66 2B 53 02"), ("int32","int32","float"), "UndertrayParams=(i,i,f)"),

    CdfFieldDef("DryTireCompoundSetting",  "GENERAL", hx("26 E4 A7 89 37"), ("byte",),                 "DryTireCompoundSetting={byte}"),
    CdfFieldDef("WetTireCompoundSetting",  "GENERAL", hx("26 7B 83 4D 10"), ("byte",),                 "WetTireCompoundSetting={byte}"),
    CdfFieldDef("IceTireCompoundSetting",  "GENERAL", hx("26 A4 F8 37 C0"), ("byte",),                 "IceTireCompoundSetting={byte}"),
    CdfFieldDef("AllTerrainTireCompoundSetting","GENERAL", hx("26 F7 FA A8 5D"), ("byte",),            "AllTerrainTireCompoundSetting={byte}"),

    CdfFieldDef("FuelRange",               "GENERAL", hx("24 19 38 99 74 A3 00"), ("float","float","byte"), "FuelRange=(f,f,b)"),
    CdfFieldDef("FuelSetting",             "GENERAL", hx("20 99 F0 BB F8"), ("byte",),                 "FuelSetting={byte}"),

    CdfFieldDef("NumPitstopsRange",        "GENERAL", hx("24 F7 05 73 EA 03 00"), ("byte","byte","byte"), "NumPitstopsRange=(b,b,b)"),
    CdfFieldDef("NumPitstopsSetting",      "GENERAL", hx("20 6D DE 02 E8"), ("byte",),                 "NumPitstopsSetting={byte}"),

    CdfFieldDef("PitstopOneRange",         "GENERAL", hx("24 9B FA 80 6D 83 00"), ("byte","float","byte"), "PitstopOneRange=(b,f,b)"),
    CdfFieldDef("PitstopOneSetting",       "GENERAL", hx("20 03 EE A8 65"), ("byte",),                 "PitstopOneSetting={byte}"),

    CdfFieldDef("PitstopTwoRange",         "GENERAL", hx("24 55 DE D0 64 83 00"), ("byte","float","byte"), "PitstopTwoRange=(b,f,b)"),
    CdfFieldDef("PitstopTwoSetting",       "GENERAL", hx("20 85 22 52 46"), ("byte",),                 "PitstopTwoSetting={byte}"),

    CdfFieldDef("PitstopThreeRange",       "GENERAL", hx("24 E8 12 23 11 83 00"), ("byte","float","byte"), "PitstopThreeRange=(b,f,b)"),
    CdfFieldDef("PitstopThreeSetting",     "GENERAL", hx("20 26 BA 51 7D"), ("byte",),                 "PitstopThreeSetting={byte}"),

    CdfFieldDef("AIMinPassesPerTick",      "GENERAL", hx("20 BB 1F 05 F3"), ("byte",),                 "AIMinPassesPerTick={byte}"),
    CdfFieldDef("AIRotationThreshold",     "GENERAL", hx("22 26 A9 8C 99"), ("float",),                "AIRotationThreshold={float}"),
    CdfFieldDef("AIEvenSuspension",        "GENERAL", hx("22 79 F4 A6 98"), ("float",),                "AIEvenSuspension={float}"),
    CdfFieldDef("AISpringRate",            "GENERAL", hx("22 BC C7 CE E7"), ("float",),                "AISpringRate={float}"),
    CdfFieldDef("AIDamperSlow",            "GENERAL", hx("22 2B 3F F8 6B"), ("float",),                "AIDamperSlow={float}"),
    CdfFieldDef("AIDamperFast",            "GENERAL", hx("22 C4 89 77 69"), ("float",),                "AIDamperFast={float}"),
    CdfFieldDef("AIDownforceZArm",         "GENERAL", hx("22 88 76 9A ED"), ("float",),                "AIDownforceZArm={float}"),
    CdfFieldDef("AIDownforceBias",         "GENERAL", hx("22 15 6B 48 37"), ("float",),                "AIDownforceBias={float}"),
    CdfFieldDef("AITorqueStab",            "GENERAL", hx("24 2E 5D 54 E4 A3 02"), ("float","float","float"), "AITorqueStab=(f,f,f)"),

    # =========================
    # FRONT WING
    # =========================
    CdfFieldDef("FWRange",                 "FRONT WING", hx("24 AD 3C 20 13 83 00"), ("byte","float","byte"), "FWRange=(b,f,b)"),
    CdfFieldDef("FWSetting",               "FRONT WING", hx("20 06 A3 1F 94"), ("byte",),                 "FWSetting={byte}"),
    CdfFieldDef("FWMaxHeight",             "FRONT WING", hx("24 09 A8 52 D9 21"), ("float",),                "FWMaxHeight={float}"),
    CdfFieldDef("FWDragParams",            "FRONT WING", hx("24 2C FB 70 DA A3 02"), ("float","float","float"), "FWDragParams=(f,f,f)"),
    CdfFieldDef("FWLiftParams",            "FRONT WING", hx("24 23 EC 21 2A A3 02"), ("float","float","float"), "FWLiftParams=(f,f,f)"),
    CdfFieldDef("FWLiftHeight",            "FRONT WING", hx("24 06 F4 58 AC 21"), ("float",),                "FWLiftHeight={float}"),
    CdfFieldDef("FWLiftSideways",          "FRONT WING", hx("24 96 D3 8A 17 21"), ("float",),                "FWLiftSideways={float}"),

    CdfFieldDef("FWLeft",                  "FRONT WING", hx("24 54 6C CD BF A3 02"), ("float","float","float"), "FWLeft=(f,f,f)"),
    CdfFieldDef("FWRight",                 "FRONT WING", hx("24 C5 19 77 0C A3 02"), ("float","float","float"), "FWRight=(f,f,f)"),
    CdfFieldDef("FWUp",                    "FRONT WING", hx("24 CD 98 5A 4C A3 02"), ("float","float","float"), "FWUp=(f,f,f)"),
    CdfFieldDef("FWDown",                  "FRONT WING", hx("24 82 6E D8 E3 A3 02"), ("float","float","float"), "FWDown=(f,f,f)"),
    CdfFieldDef("FWAft",                   "FRONT WING", hx("24 E4 3E 99 D8 A3 02"), ("float","float","float"), "FWAft=(f,f,f)"),
    CdfFieldDef("FWFore",                  "FRONT WING", hx("24 F5 42 E8 78 A3 02"), ("float","float","float"), "FWFore=(f,f,f)"),
    CdfFieldDef("FWRot",                   "FRONT WING", hx("24 3D FD AB 72 A3 02"), ("float","float","float"), "FWRot=(f,f,f)"),
    CdfFieldDef("FWCenter",                "FRONT WING", hx("24 EB DD A8 12 A3 02"), ("float","float","float"), "FWCenter=(f,f,f)"),

    # =========================
    # FRONT RIGHT WING
    # =========================
    CdfFieldDef("FRWRange",                "FRONT RIGHT WING", hx("24 96 A7 D0 8D 83 00"), ("byte","float","byte"), "FRWRange=(b,f,b)"),
    CdfFieldDef("FRWSetting",              "FRONT RIGHT WING", hx("20 B5 E8 1B 09"), ("byte",),               "FRWSetting={byte}"),
    CdfFieldDef("FRWMaxHeight",            "FRONT RIGHT WING", hx("24 29 1A 69 42 21"), ("float",),              "FRWMaxHeight={float}"),
    CdfFieldDef("FRWDragParams",           "FRONT RIGHT WING", hx("24 CF 8B E1 A1 A3 02"), ("float","float","float"), "FRWDragParams=(f,f,f)"),
    CdfFieldDef("FRWLiftParams",           "FRONT RIGHT WING", hx("24 76 29 1C 37 A3 02"), ("float","float","float"), "FRWLiftParams=(f,f,f)"),
    CdfFieldDef("FRWLiftHeight",           "FRONT RIGHT WING", hx("24 4B 1A 06 AD 21"), ("float",),              "FRWLiftHeight={float}"),
    CdfFieldDef("FRWLiftSideways",         "FRONT RIGHT WING", hx("24 81 05 80 FE 21"), ("float",),              "FRWLiftSideways={float}"),

    CdfFieldDef("FRWLeft",                 "FRONT RIGHT WING", hx("24 A3 72 BD EE A3 02"), ("float","float","float"), "FRWLeft=(f,f,f)"),
    CdfFieldDef("FRWRight",                "FRONT RIGHT WING", hx("24 E3 C5 15 C2 A3 02"), ("float","float","float"), "FRWRight=(f,f,f)"),
    CdfFieldDef("FRWUp",                   "FRONT RIGHT WING", hx("24 68 D5 13 6E A3 02"), ("float","float","float"), "FRWUp=(f,f,f)"),
    CdfFieldDef("FRWDown",                 "FRONT RIGHT WING", hx("24 41 68 8B 03 A3 02"), ("float","float","float"), "FRWDown=(f,f,f)"),
    CdfFieldDef("FRWAft",                  "FRONT RIGHT WING", hx("24 57 1E 68 BD A3 02"), ("float","float","float"), "FRWAft=(f,f,f)"),
    CdfFieldDef("FRWFore",                 "FRONT RIGHT WING", hx("24 91 B8 03 C5 A3 02"), ("float","float","float"), "FRWFore=(f,f,f)"),
    CdfFieldDef("FRWRot",                  "FRONT RIGHT WING", hx("24 7B 00 64 6A A3 02"), ("float","float","float"), "FRWRot=(f,f,f)"),
    CdfFieldDef("FRWCenter",               "FRONT RIGHT WING", hx("24 87 7F E1 43 A3 02"), ("float","float","float"), "FRWCenter=(f,f,f)"),

    # =========================
    # REAR WING
    # =========================
    CdfFieldDef("RWRange",                 "REAR WING", hx("24 15 76 54 86 83 00"), ("byte","float","byte"), "RWRange=(b,f,b)"),
    CdfFieldDef("RWSetting",               "REAR WING", hx("20 8A 98 EB 35"), ("byte",),                 "RWSetting={byte}"),
    CdfFieldDef("RWDragParams",            "REAR WING", hx("24 67 DC B6 B3 A3 02"), ("float","float","float"), "RWDragParams=(f,f,f)"),
    CdfFieldDef("RWLiftParams",            "REAR WING", hx("24 83 D3 85 B9 A3 02"), ("float","float","float"), "RWLiftParams=(f,f,f)"),
    CdfFieldDef("RWLiftSideways",          "REAR WING", hx("24 7A 8F 77 C8 21"), ("float",),                "RWLiftSideways={float}"),
    CdfFieldDef("RWPeakYaw",               "REAR WING", hx("24 15 2E 20 37 A2"), ("float","float"),         "RWPeakYaw=(f,f)"),

    CdfFieldDef("RWLeft",                  "REAR WING", hx("24 34 3E C4 2F A3 02"), ("float","float","float"), "RWLeft=(f,f,f)"),
    CdfFieldDef("RWRight",                 "REAR WING", hx("24 42 3B C2 6A A3 02"), ("float","float","float"), "RWRight=(f,f,f)"),
    CdfFieldDef("RWUp",                    "REAR WING", hx("24 EF B4 24 0A A3 02"), ("float","float","float"), "RWUp=(f,f,f)"),
    CdfFieldDef("RWDown",                  "REAR WING", hx("24 65 F8 14 22 A3 02"), ("float","float","float"), "RWDown=(f,f,f)"),
    CdfFieldDef("RWAft",                   "REAR WING", hx("24 69 EC ED 3E A3 02"), ("float","float","float"), "RWAft=(f,f,f)"),
    CdfFieldDef("RWFore",                  "REAR WING", hx("24 D5 07 F8 FE A3 02"), ("float","float","float"), "RWFore=(f,f,f)"),
    CdfFieldDef("RWRot",                   "REAR WING", hx("24 08 4B 50 B3 A3 02"), ("float","float","float"), "RWRot=(f,f,f)"),
    CdfFieldDef("RWCenter",                "REAR WING", hx("24 17 44 ED 31 A3 02"), ("float","float","float"), "RWCenter=(f,f,f)"),

    # =========================
    # REAR RIGHT WING (raw/odd block from paste)
    # =========================
    CdfFieldDef("RRWRange",                "REAR RIGHT WING", hx("24 1F 3D 69 0C 03 00"), ("byte","byte","byte"), "RRWRange=(b,b,b)"),
    CdfFieldDef("RRWSetting",              "REAR RIGHT WING", hx("28 85 98 3C 01"), (),                        "RRWSetting=default"),
    CdfFieldDef("RRWDragParams",           "REAR RIGHT WING", hx("24 6B 20 03 55 23 00"), ("float","byte","byte"), "RRWDragParams=(f,b,b)"),
    CdfFieldDef("RRWLiftParams",           "REAR RIGHT WING", hx("24 B8 2D 4D C4 03 00"), ("byte","byte","byte"), "RRWLiftParams=(b,b,b)"),
    CdfFieldDef("RRWLiftSideways",         "REAR RIGHT WING", hx("24 0A 2B 9B 22 01"), ("byte",),               "RRWLiftSideways={byte}"),
    CdfFieldDef("RRWPeakYaw",              "REAR RIGHT WING", hx("24 BD CD 13 89 02"), ("byte","byte"),         "RRWPeakYaw=(b,b)"),
    CdfFieldDef("RRWLeft",                 "REAR RIGHT WING", hx("24 22 45 69 35 03 00"), ("byte","byte","byte"), "RRWLeft=(b,b,b)"),
    CdfFieldDef("RRWRight",                "REAR RIGHT WING", hx("24 51 1B 19 80 03 00"), ("byte","byte","byte"), "RRWRight=(b,b,b)"),
    CdfFieldDef("RRWUp",                   "REAR RIGHT WING", hx("24 86 1A F2 5C 03 00"), ("byte","byte","byte"), "RRWUp=(b,b,b)"),
    CdfFieldDef("RRWDown",                 "REAR RIGHT WING", hx("24 51 EE 77 72 03 00"), ("byte","byte","byte"), "RRWDown=(b,b,b)"),
    CdfFieldDef("RRWAft",                  "REAR RIGHT WING", hx("24 46 77 39 74 03 00"), ("byte","byte","byte"), "RRWAft=(b,b,b)"),
    CdfFieldDef("RRWFore",                 "REAR RIGHT WING", hx("24 2B 7E E4 47 03 00"), ("byte","byte","byte"), "RRWFore=(b,b,b)"),
    CdfFieldDef("RRWRot",                  "REAR RIGHT WING", hx("24 99 E7 CC 64 03 00"), ("byte","byte","byte"), "RRWRot=(b,b,b)"),
    CdfFieldDef("RRWCenter",               "REAR RIGHT WING", hx("24 8D 6C 15 A3 83 02"), ("byte","float","float"), "RRWCenter=(b,f,f)"),

    # =========================
    # BODY AERO
    # =========================
    CdfFieldDef("BodyDragBase",            "BODY AERO", hx("24 33 63 ED FD 21"), ("float",), "BodyDragBase={float}"),
    CdfFieldDef("BodyDragHeightAvg",       "BODY AERO", hx("24 67 CA A0 92 21"), ("float",), "BodyDragHeightAvg={float}"),
    CdfFieldDef("BodyDragHeightDiff",      "BODY AERO", hx("24 1F 13 C1 85 21"), ("float",), "BodyDragHeightDiff={float}"),
    CdfFieldDef("BodyMaxHeight",           "BODY AERO", hx("24 56 E0 A3 AB 21"), ("float",), "BodyMaxHeight={float}"),

    CdfFieldDef("BodyLeft",                "BODY AERO", hx("24 C5 A5 4E CE A3 02"), ("float","float","float"), "BodyLeft=(f,f,f)"),
    CdfFieldDef("BodyRight",               "BODY AERO", hx("24 6A 08 2A D4 A3 02"), ("float","float","float"), "BodyRight=(f,f,f)"),
    CdfFieldDef("BodyUp",                  "BODY AERO", hx("24 DC 57 D2 48 A3 02"), ("float","float","float"), "BodyUp=(f,f,f)"),
    CdfFieldDef("BodyDown",                "BODY AERO", hx("24 E3 A1 65 97 A3 02"), ("float","float","float"), "BodyDown=(f,f,f)"),
    CdfFieldDef("BodyAft",                 "BODY AERO", hx("24 08 B1 B6 50 A3 02"), ("float","float","float"), "BodyAft=(f,f,f)"),
    CdfFieldDef("BodyFore",                "BODY AERO", hx("24 DC 2F 52 E4 A3 02"), ("float","float","float"), "BodyFore=(f,f,f)"),
    CdfFieldDef("BodyRot",                 "BODY AERO", hx("24 F8 26 31 A8 A3 02"), ("float","float","float"), "BodyRot=(f,f,f)"),
    CdfFieldDef("BodyCenter",              "BODY AERO", hx("24 38 D1 8E E7 A3 02"), ("float","float","float"), "BodyCenter=(f,f,f)"),

    CdfFieldDef("RadiatorRange",           "BODY AERO", hx("24 8E 02 D1 67 83 00"), ("byte","float","byte"), "RadiatorRange=(b,f,b)"),
    CdfFieldDef("RadiatorSetting",         "BODY AERO", hx("20 F7 CF 3C A8"), ("byte",), "RadiatorSetting={byte}"),
    CdfFieldDef("RadiatorDrag",            "BODY AERO", hx("24 CD 9B D5 4E 21"), ("float",), "RadiatorDrag={float}"),
    CdfFieldDef("RadiatorLift",            "BODY AERO", hx("24 0A 98 AA BD 21"), ("float",), "RadiatorLift={float}"),

    CdfFieldDef("BrakeDuctRange",          "BODY AERO", hx("24 67 64 39 31 83 00"), ("byte","float","byte"), "BrakeDuctRange=(b,f,b)"),
    CdfFieldDef("BrakeDuctSetting",        "BODY AERO", hx("20 CF 01 35 71"), ("byte",), "BrakeDuctSetting={byte}"),
    CdfFieldDef("BrakeDuctDrag",           "BODY AERO", hx("24 50 2D C5 AE 21"), ("float",), "BrakeDuctDrag={float}"),
    CdfFieldDef("BrakeDuctLift",           "BODY AERO", hx("24 B7 28 36 3E 21"), ("float",), "BrakeDuctLift={float}"),

    # =========================
    # DIFFUSER
    # =========================
    CdfFieldDef("DiffuserBase",            "DIFFUSER", hx("24 BE 0F 28 99 A3 02"), ("float","float","float"), "DiffuserBase=(f,f,f)"),
    CdfFieldDef("DiffuserFrontHeight",     "DIFFUSER", hx("24 47 D0 B1 DE 21"), ("float",), "DiffuserFrontHeight={float}"),
    CdfFieldDef("DiffuserRake",            "DIFFUSER", hx("24 20 B9 8D FF A3 02"), ("float","float","float"), "DiffuserRake=(f,f,f)"),
    CdfFieldDef("DiffuserLimits",          "DIFFUSER", hx("24 FF 59 46 C8 A3 02"), ("float","float","float"), "DiffuserLimits=(f,f,f)"),
    CdfFieldDef("DiffuserStall",           "DIFFUSER", hx("24 E0 A1 25 DE A2"), ("float","float"), "DiffuserStall=(f,f)"),
    CdfFieldDef("DiffuserSideways",        "DIFFUSER", hx("24 E1 76 32 24 21"), ("float",), "DiffuserSideways={float}"),
    CdfFieldDef("DiffuserCenter",          "DIFFUSER", hx("24 B8 97 56 8E A3 02"), ("float","float","float"), "DiffuserCenter=(f,f,f)"),

    # =========================
    # SUSPENSION
    # =========================
    CdfFieldDef("AdjustSuspRates",         "SUSPENSION", hx("20 7D E0 90 64"), ("byte",), "AdjustSuspRates={byte}"),
    CdfFieldDef("AlignWheels",             "SUSPENSION", hx("20 B2 B4 93 40"), ("byte",), "AlignWheels={byte}"),
    CdfFieldDef("SpringBasedAntiSway",     "SUSPENSION", hx("20 26 E9 82 B6"), ("byte",), "SpringBasedAntiSway={byte}"),

    CdfFieldDef("FrontAntiSwayBase",       "SUSPENSION", hx("28 89 92 C5 F3"), (), "FrontAntiSwayBase=default"),
    CdfFieldDef("FrontAntiSwayRange",      "SUSPENSION", hx("24 E5 B9 A9 D6 A3 00"), ("float","float","byte"), "FrontAntiSwayRange=(f,f,b)"),
    CdfFieldDef("FrontAntiSwaySetting",    "SUSPENSION", hx("20 7F C7 58 D5"), ("byte",), "FrontAntiSwaySetting={byte}"),
    CdfFieldDef("FrontAntiSwayRate",       "SUSPENSION", hx("24 2E 06 8D A5 A2"), ("float","float"), "FrontAntiSwayRate=(f,f)"),

    CdfFieldDef("RearAntiSwayRange",       "SUSPENSION", hx("24 66 00 1E 25 A3 00"), ("float","float","byte"), "RearAntiSwayRange=(f,f,b)"),
    CdfFieldDef("RearAntiSwaySetting",     "SUSPENSION", hx("20 04 78 E9 91"), ("byte",), "RearAntiSwaySetting={byte}"),
    CdfFieldDef("RearAntiSwayRate",        "SUSPENSION", hx("24 50 E0 77 73 A2"), ("float","float"), "RearAntiSwayRate=(f,f)"),

    CdfFieldDef("FrontToeInRange",         "SUSPENSION", hx("24 69 D4 9B 3B A3 00"), ("float","float","byte"), "FrontToeInRange=(f,f,b)"),
    CdfFieldDef("FrontToeInSetting",       "SUSPENSION", hx("20 C3 36 57 CC"), ("byte",), "FrontToeInSetting={byte}"),

    CdfFieldDef("RearToeInRange",          "SUSPENSION", hx("24 55 C9 EA 65 A3 00"), ("float","float","byte"), "RearToeInRange=(f,f,b)"),
    CdfFieldDef("RearToeInSetting",        "SUSPENSION", hx("20 FD F7 43 4F"), ("byte",), "RearToeInSetting={byte}"),

    CdfFieldDef("LeftCasterRange",         "SUSPENSION", hx("24 1A 73 FE 3E A3 00"), ("float","float","byte"), "LeftCasterRange=(f,f,b)"),
    CdfFieldDef("LeftCasterSetting",       "SUSPENSION", hx("20 FF D7 A7 D9"), ("byte",), "LeftCasterSetting={byte}"),

    CdfFieldDef("RightCasterRange",        "SUSPENSION", hx("24 33 76 33 73 A3 00"), ("float","float","byte"), "RightCasterRange=(f,f,b)"),
    CdfFieldDef("RightCasterSetting",      "SUSPENSION", hx("20 A6 B8 E3 8F"), ("byte",), "RightCasterSetting={byte}"),

    # =========================
    # CONTROLS
    # =========================
    CdfFieldDef("SteeringFFBMult",         "CONTROLS", hx("22 24 F5 34 B3"), ("float",), "SteeringFFBMult={float}"),
    CdfFieldDef("FFBGripMulti",            "CONTROLS", hx("22 FB 38 19 1C"), ("float",), "FFBGripMulti={float}"),

    CdfFieldDef("SteeringRatioRange",      "CONTROLS", hx("24 6B 4E A0 77 A3 00"), ("float","float","byte"), "SteeringRatioRange=(f,f,b)"),
    CdfFieldDef("SteeringRatioSetting",    "CONTROLS", hx("20 0F 6A B7 B6"), ("byte",), "SteeringRatioSetting={byte}"),

    CdfFieldDef("CDF_UNKN_006",            "CONTROLS", hx("22 27 A0 D3 AC"), ("float",), "CDF_UNKN_006={float}"),
    CdfFieldDef("CDF_UNKN_007",            "CONTROLS", hx("20 31 7B 74 DC"), ("byte",),  "CDF_UNKN_007={byte}"),
    CdfFieldDef("CDF_UNKN_008",            "CONTROLS", hx("22 E8 09 B9 01"), ("float",), "CDF_UNKN_008={float}"),

    CdfFieldDef("CDF_UNKN_011",            "CONTROLS", hx("22 20 D5 05 AC"), ("float",), "CDF_UNKN_011={float}"),
    # paste was inconsistent; keeping float because of 22-prefix, same approach as before
    CdfFieldDef("CDF_UNKN_012",            "CONTROLS", hx("22 48 E1 7A 3F"), ("float",), "CDF_UNKN_012={float}"),

    CdfFieldDef("UpshiftAlgorithm",        "CONTROLS", hx("24 E0 D9 C8 5B 22"), ("float","byte"), "UpshiftAlgorithm=(f,b)"),
    CdfFieldDef("DownshiftAlgorithm",      "CONTROLS", hx("24 A6 8D 9C E2 A3 02"), ("float","float","float"), "DownshiftAlgorithm=(f,f,f)"),

    CdfFieldDef("SteeringLockRange",       "CONTROLS", hx("24 30 43 CE 21 23 00"), ("float","byte","byte"), "SteeringLockRange=(f,b,b)"),
    CdfFieldDef("SteeringLockSetting",     "CONTROLS", hx("28 B7 C2 C5 7E"), (), "SteeringLockSetting=default"),

    CdfFieldDef("Unkn_0x2205CF7B77",       "CONTROLS", hx("22 05 CF 7B 77"), ("float",), "Unkn_0x2205CF7B77={float}"),
    CdfFieldDef("Unkn_0x2252FA3411",       "CONTROLS", hx("22 52 FA 34 11"), ("float",), "Unkn_0x2252FA3411={float}"),

    CdfFieldDef("RearBrakeRange",          "CONTROLS", hx("24 A6 32 13 57 83 00"), ("byte","float","byte"), "RearBrakeRange=(b,f,b)"),
    CdfFieldDef("RearBrakeSetting",        "CONTROLS", hx("20 FD BA 64 73"), ("byte",), "RearBrakeSetting={byte}"),

    CdfFieldDef("BrakePressureRange",      "CONTROLS", hx("24 D0 00 38 59 A3 00"), ("float","float","byte"), "BrakePressureRange=(f,f,b)"),
    CdfFieldDef("BrakePressureSetting",    "CONTROLS", hx("20 DA BD B9 81"), ("byte",), "BrakePressureSetting={byte}"),

    CdfFieldDef("HandbrakeRange",          "CONTROLS", hx("24 96 4B 29 B4 83 00"), ("byte","float","byte"), "HandbrakeRange=(b,f,b)"),
    CdfFieldDef("HandbrakePressSetting",   "CONTROLS", hx("20 52 30 1F D2"), ("byte",), "HandbrakePressSetting={byte}"),

    CdfFieldDef("AutoUpshiftGripThresh",   "CONTROLS", hx("22 E3 5A 1D CA"), ("float",), "AutoUpshiftGripThresh={float}"),
    CdfFieldDef("AutoDownshiftGripThresh", "CONTROLS", hx("22 33 DE 0B C9"), ("float",), "AutoDownshiftGripThresh={float}"),

    CdfFieldDef("TractionControlGrip",     "CONTROLS", hx("24 07 F7 6E 47 A2"), ("float","float"), "TractionControlGrip=(f,f)"),
    CdfFieldDef("TractionControlLevel",    "CONTROLS", hx("24 25 5A FB 23 A2"), ("float","float"), "TractionControlLevel=(f,f)"),

    CdfFieldDef("ABSStrengthRange",        "CONTROLS", hx("24 24 9E 03 13 83 00"), ("byte","float","byte"), "ABSStrengthRange=(b,f,b)"),
    CdfFieldDef("ABSStrengthSetting",      "CONTROLS", hx("20 B2 BE 8E 7E"), ("byte",), "ABSStrengthSetting={byte}"),

    CdfFieldDef("CDF_UNKN_016",            "CONTROLS", hx("20 FA CE 76 12"), ("byte",), "CDF_UNKN_016={byte}"),
    CdfFieldDef("CDF_UNKN_017",            "CONTROLS", hx("20 D5 DD 9C 9B"), ("byte",), "CDF_UNKN_017={byte}"),
    CdfFieldDef("CDF_UNKN_018",            "CONTROLS", hx("20 5B D1 F7 C8"), ("byte",), "CDF_UNKN_018={byte}"),

    CdfFieldDef("CDF_UNKN_019",            "CONTROLS", hx("24 64 70 F5 FD 83 02"), ("byte","float","float"), "CDF_UNKN_019=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_020",            "CONTROLS", hx("20 34 76 EE E3"), ("byte",), "CDF_UNKN_020={byte}"),

    CdfFieldDef("CDF_UNKN_021",            "CONTROLS", hx("24 C8 1B AC AF 83 02"), ("byte","float","float"), "CDF_UNKN_021=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_022",            "CONTROLS", hx("20 61 5A 10 D6"), ("byte",), "CDF_UNKN_022={byte}"),

    CdfFieldDef("CDF_UNKN_023",            "CONTROLS", hx("24 D2 2F 18 AF 83 02"), ("byte","float","float"), "CDF_UNKN_023=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_024",            "CONTROLS", hx("20 4D CA 34 17"), ("byte",), "CDF_UNKN_024={byte}"),

    CdfFieldDef("CDF_UNKN_025",            "CONTROLS", hx("24 B3 85 4E E0 83 02"), ("byte","float","float"), "CDF_UNKN_025=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_026",            "CONTROLS", hx("20 6C E5 6E 1B"), ("byte",), "CDF_UNKN_026={byte}"),

    CdfFieldDef("CDF_UNKN_027",            "CONTROLS", hx("24 72 DE E1 17 83 02"), ("byte","float","float"), "CDF_UNKN_027=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_028",            "CONTROLS", hx("20 99 3F 2A 3F"), ("byte",), "CDF_UNKN_028={byte}"),

    CdfFieldDef("CDF_UNKN_029",            "CONTROLS", hx("24 5A AE 27 42 83 02"), ("byte","float","float"), "CDF_UNKN_029=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_030",            "CONTROLS", hx("20 25 F7 FA 9E"), ("byte",), "CDF_UNKN_030={byte}"),

    CdfFieldDef("CDF_UNKN_031",            "CONTROLS", hx("24 7A 49 7E 24 83 02"), ("byte","float","float"), "CDF_UNKN_031=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_031_Setting",    "CONTROLS", hx("28 99 85 60 E9"), (), "CDF_UNKN_031_Setting=default"),

    CdfFieldDef("CDF_UNKN_032",            "CONTROLS", hx("24 25 8E 3F 20 83 02"), ("byte","float","float"), "CDF_UNKN_032=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_032_Setting",    "CONTROLS", hx("28 3C 50 F8 D7"), (), "CDF_UNKN_032_Setting=default"),

    CdfFieldDef("CDF_UNKN_033",            "CONTROLS", hx("24 6A 7D 42 63 83 02"), ("byte","float","float"), "CDF_UNKN_033=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_033_Setting",    "CONTROLS", hx("28 A9 F7 13 BD"), (), "CDF_UNKN_033_Setting=default"),

    CdfFieldDef("CDF_UNKN_034",            "CONTROLS", hx("24 98 CA 4E 61 03 02"), ("byte","byte","byte"), "CDF_UNKN_034=(b,b,b)"),
    CdfFieldDef("CDF_UNKN_034_Setting",    "CONTROLS", hx("20 77 E8 4F 5C"), ("byte",), "CDF_UNKN_034_Setting={byte}"),

    CdfFieldDef("CDF_UNKN_035",            "CONTROLS", hx("24 09 DE B7 68 83 02"), ("byte","float","float"), "CDF_UNKN_035=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_035_Setting",    "CONTROLS", hx("28 FF 26 A3 2B"), (), "CDF_UNKN_035_Setting=default"),

    CdfFieldDef("CDF_UNKN_036",            "CONTROLS", hx("24 4B D5 82 72 83 02"), ("byte","float","float"), "CDF_UNKN_036=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_036_Setting",    "CONTROLS", hx("28 E5 12 C1 5D"), (), "CDF_UNKN_036_Setting=default"),

    CdfFieldDef("CDF_UNKN_037",            "CONTROLS", hx("24 22 AC 0C 3A 83 02"), ("byte","float","float"), "CDF_UNKN_037=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_037_Setting",    "CONTROLS", hx("20 17 7A 98 F5"), ("byte",), "CDF_UNKN_037_Setting={byte}"),

    CdfFieldDef("CDF_UNKN_039",            "CONTROLS", hx("24 9F C7 1E D1 83 02"), ("byte","float","float"), "CDF_UNKN_039=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_040",            "CONTROLS", hx("20 C7 D5 99 C6"), ("byte",), "CDF_UNKN_040={byte}"),

    CdfFieldDef("CDF_UNKN_041",            "CONTROLS", hx("24 67 8C A5 99 83 02"), ("byte","float","float"), "CDF_UNKN_041=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_041_Setting",    "CONTROLS", hx("28 BE A1 5C E1"), (), "CDF_UNKN_041_Setting=default"),

    CdfFieldDef("CDF_UNKN_042",            "CONTROLS", hx("24 8E 47 3C 20 83 02"), ("byte","float","float"), "CDF_UNKN_042=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_042_Setting",    "CONTROLS", hx("28 ED 5F B5 79"), (), "CDF_UNKN_042_Setting=default"),

    CdfFieldDef("CDF_UNKN_043",            "CONTROLS", hx("24 23 F0 43 98 83 02"), ("byte","float","float"), "CDF_UNKN_043=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_043_Setting",    "CONTROLS", hx("28 CA E1 FE 39"), (), "CDF_UNKN_043_Setting=default"),

    CdfFieldDef("CDF_UNKN_044",            "CONTROLS", hx("24 E7 6C F5 65 83 02"), ("byte","float","float"), "CDF_UNKN_044=(b,f,f)"),
    CdfFieldDef("CDF_UNKN_044_Setting",    "CONTROLS", hx("28 31 6F DC CC"), (), "CDF_UNKN_044_Setting=default"),

    # =========================
    # DRIVELINE (only what was present in the pasted excerpt)
    # =========================
    CdfFieldDef("ClutchEngageRate",        "DRIVELINE", hx("22 1B CA 33 55"), ("float",), "ClutchEngageRate={float}"),
    CdfFieldDef("ClutchInertia",           "DRIVELINE", hx("22 D3 1C F6 C6"), ("float",), "ClutchInertia={float}"),
    CdfFieldDef("ClutchTorque",            "DRIVELINE", hx("22 2E 33 DB 70"), ("float",), "ClutchTorque={float}"),
    CdfFieldDef("ClutchFriction",          "DRIVELINE", hx("22 9B 56 A1 18"), ("float",), "ClutchFriction={float}"),
    CdfFieldDef("BaulkTorque",             "DRIVELINE", hx("22 36 6E 87 07"), ("float",), "BaulkTorque={float}"),

    CdfFieldDef("SemiAutomatic",           "DRIVELINE", hx("20 1D EA 4C 3D"), ("byte",), "SemiAutomatic={byte}"),
    CdfFieldDef("CDF_UNKN_046",            "DRIVELINE", hx("20 74 73 B2 00"), ("byte",), "CDF_UNKN_046={byte}"),
    CdfFieldDef("CDF_UNKN_047",            "DRIVELINE", hx("20 B5 19 EF 5C"), ("byte",), "CDF_UNKN_047={byte}"),

    CdfFieldDef("UpshiftDelay",            "DRIVELINE", hx("22 67 F7 AD 20"), ("float",), "UpshiftDelay={float}"),
    CdfFieldDef("UpshiftClutchTime",       "DRIVELINE", hx("22 9D 78 9E C9"), ("float",), "UpshiftClutchTime={float}"),
    CdfFieldDef("DownshiftDelay",          "DRIVELINE", hx("22 07 50 AF 26"), ("float",), "DownshiftDelay={float}"),
    CdfFieldDef("DownshiftClutchTime",     "DRIVELINE", hx("22 DB 0B FC 09"), ("float",), "DownshiftClutchTime={float}"),
    CdfFieldDef("DownshiftBlipThrottle",   "DRIVELINE", hx("22 3B 62 D3 1C"), ("float",), "DownshiftBlipThrottle={float}"),

    CdfFieldDef("FinalDriveSetting",       "DRIVELINE", hx("20 C1 EB DC 28"), ("byte",), "FinalDriveSetting={byte}"),
    CdfFieldDef("ReverseGearSetting",      "DRIVELINE", hx("28 D6 71 85 B0"), (),       "ReverseGearSetting=default"),
    CdfFieldDef("ForwardGears",            "DRIVELINE", hx("20 FF 0C 22 07"), ("byte",), "ForwardGears={byte}"),

    CdfFieldDef("GearOneSetting",          "DRIVELINE", hx("28 F4 CC 2F 1D"), (),       "GearOneSetting=default"),
    CdfFieldDef("GearTwoSetting",          "DRIVELINE", hx("20 8D 69 C2 DA"), ("byte",), "GearTwoSetting={byte}"),
    CdfFieldDef("GearThreeSetting",        "DRIVELINE", hx("20 C0 25 93 C3"), ("byte",), "GearThreeSetting={byte}"),
    CdfFieldDef("GearFourSetting",         "DRIVELINE", hx("20 78 92 B7 5A"), ("byte",), "GearFourSetting={byte}"),
    CdfFieldDef("GearFiveSetting",         "DRIVELINE", hx("20 78 4E 48 36"), ("byte",), "GearFiveSetting={byte}"),
    CdfFieldDef("GearSixSetting",          "DRIVELINE", hx("20 5F 2B A9 EE"), ("byte",), "GearSixSetting={byte}"),
]



# -----------------------------
# Hex view helpers
# -----------------------------
def is_printable(b: int) -> bool:
    return 32 <= b <= 126

def format_hex_lines(blob: bytes, start: int, nbytes: int, bytes_per_line: int = 16) -> List[str]:
    """Return classic hex dump lines (offset  hex...  ascii)."""
    end = min(len(blob), start + nbytes)
    lines: List[str] = []
    for off in range(start, end, bytes_per_line):
        chunk = blob[off:off+bytes_per_line]
        hex_part = " ".join(f"{x:02X}" for x in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(x) if is_printable(x) else "." for x in chunk)
        lines.append(f"{off:08X}  {hex_part}  |{ascii_part}|")
    return lines

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


# -----------------------------
# UI
# -----------------------------
class CdfEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CDFbin Editor")
        self.geometry("1400x820")

        self.file_path: Optional[str] = None
        self.original_blob: Optional[bytes] = None
        self.working_blob: Optional[bytes] = None
        self.instances: List[CdfFieldInstance] = []

        self.edits: Dict[Tuple[str, str, str, int], Tuple[Any, ...]] = {}

        # selection state
        self._selected_instance: Optional[CdfFieldInstance] = None
        self._editor_vars: List[tk.StringVar] = []

        # hex view state
        self.hex_bytes_per_page = 16 * 64      # 64 lines of 16 bytes = 1024 bytes per page
        self.hex_anchor = 0                    # start offset shown in hex view (aligned)
        self._hex_line_index: Dict[int, int] = {}  # offset->line map for current view
        # click-to-tree mapping: key -> iid, and offset->instance ranges
        self._cdf_iid_by_key: Dict[Tuple[str, str, str, int], str] = {}
        self._known_ranges: List[Tuple[int, int, Tuple[str, str, str, int]]] = []  # [start,end) -> key


        self._build_menu()
        self._build_layout()

    def _build_menu(self):
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Open…", command=self.open_file)
        fm.add_command(label="Save", command=self.save_file, state="disabled")
        fm.add_command(label="Save As…", command=self.save_file_as, state="disabled")
        fm.add_separator()
        fm.add_command(label="Exit", command=self.destroy)
        m.add_cascade(label="File", menu=fm)

        tm = tk.Menu(m, tearoff=0)
        tm.add_command(label="Re-parse (refresh view)", command=self.refresh_parse, state="disabled")
        tm.add_command(label="Discard unsaved edits", command=self.discard_edits, state="disabled")
        m.add_cascade(label="Tools", menu=tm)

        self.config(menu=m)
        s   self._tools_menu = tm

    def _build_layout(self):
        # vertical split: top main + bottom hex
        v = ttk.Panedwindow(self, orient="vertical")
        v.pack(fill="both", expand=True)

        # top main: left tree, right field editor
        outer = ttk.Panedwindow(v, orient="horizontal")
        v.add(outer, weight=3)

        left = ttk.Frame(outer, padding=8)
        outer.add(left, weight=3)

        right = ttk.Frame(outer, padding=8)
        outer.add(right, weight=2)

        # bottom hex viewer/editor
        hexpane = ttk.Frame(v, padding=8)
        v.add(hexpane, weight=2)

        # ---------------- left panel ----------------
        topbar = ttk.Frame(left)
        topbar.pack(fill="x", pady=(0, 6))
        
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=28)  # tweak 24–34 to tasteelf._file_menu = fm
     

        ttk.Label(topbar, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._rebuild_tree())
        ttk.Entry(topbar, textvariable=self.filter_var, width=40).pack(side="left", padx=6)

        self.status_var = tk.StringVar(value="Open a .cdfbin to begin.")
        ttk.Label(left, textvariable=self.status_var).pack(fill="x", pady=(0, 6))

        self.tree = ttk.Treeview(left, columns=("value", "type", "offset"), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Field")
        self.tree.heading("value", text="Value")
        self.tree.heading("type", text="Layout")
        self.tree.heading("offset", text="Offset (hex)")
        self.tree.column("#0", width=360)
        self.tree.column("value", width=240)
        self.tree.column("type", width=160)
        self.tree.column("offset", width=120, anchor="e")

        ysb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ---------------- right panel ----------------
        ttk.Label(right, text="Selected field", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        self.sel_title = tk.StringVar(value="(none)")
        ttk.Label(right, textvariable=self.sel_title, wraplength=500).pack(anchor="w", pady=(4, 8))

        self.meta_text = tk.Text(right, height=8, width=55, wrap="word")
        self.meta_text.configure(state="disabled")
        self.meta_text.pack(fill="x", pady=(0, 10))

        ttk.Label(right, text="Edit values", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.editor_frame = ttk.Frame(right)
        self.editor_frame.pack(fill="x", pady=(6, 10))

        btns = ttk.Frame(right)
        btns.pack(fill="x", pady=(8, 0))
        self.apply_btn = ttk.Button(btns, text="Apply Edit", command=self.apply_edit, state="disabled")
        self.apply_btn.pack(side="left")
        self.revert_btn = ttk.Button(btns, text="Revert Field", command=self.revert_field, state="disabled")
        self.revert_btn.pack(side="left", padx=8)

        ttk.Separator(right).pack(fill="x", pady=12)

        ttk.Label(right, text="Notes / Help", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.notes = tk.Text(right, height=8, wrap="word")
        self.notes.insert("1.0",
            "Hex pane:\n"
            "• Selecting a field will jump the hex view to the marker location and highlight marker+payload.\n"
            "• You can overwrite bytes in-place via the hex editor box (space-separated hex).\n\n"
            "Rules:\n"
            "• In-place only: replacement must be same byte count.\n"
            "• For definition-based fields, prefer the scalar editor; hex is for unknowns / verification.\n"
        )
        self.notes.configure(state="disabled")
        self.notes.pack(fill="both", expand=True)

        # ---------------- bottom hex pane ----------------
        hex_top = ttk.Frame(hexpane)
        hex_top.pack(fill="x", pady=(0, 6))

        ttk.Label(hex_top, text="Hex view", font=("Segoe UI", 11, "bold")).pack(side="left")

        ttk.Label(hex_top, text="Jump to offset (hex):").pack(side="left", padx=(16, 4))
        self.jump_var = tk.StringVar(value="0")
        jump_entry = ttk.Entry(hex_top, textvariable=self.jump_var, width=12)
        jump_entry.pack(side="left")
        ttk.Button(hex_top, text="Go", command=self.hex_jump).pack(side="left", padx=6)

        ttk.Button(hex_top, text="◀ Prev", command=lambda: self.hex_page(-1)).pack(side="left", padx=(16, 4))
        ttk.Button(hex_top, text="Next ▶", command=lambda: self.hex_page(+1)).pack(side="left")

        self.hex_info_var = tk.StringVar(value="")
        ttk.Label(hex_top, textvariable=self.hex_info_var).pack(side="right")

        # hex dump text
        hex_mid = ttk.Frame(hexpane)
        hex_mid.pack(fill="both", expand=True)

        self.hex_text = tk.Text(hex_mid, height=18, wrap="none")
        self.hex_text.configure(font=("Consolas", 10))
        self.hex_text.tag_configure("sel_marker", background="#FFF2CC")  # pale yellow
        self.hex_text.tag_configure("sel_value",  background="#D9EAD3")  # pale green
        self.hex_text.tag_configure("sel_both",   background="#D0E0E3")  # pale blue
        self.hex_text.configure(state="disabled")
        # click in hex view should jump selection in tree (if known)
        self.hex_text.bind("<Button-1>", self._on_hex_click)


        xsb = ttk.Scrollbar(hex_mid, orient="horizontal", command=self.hex_text.xview)
        ysb2 = ttk.Scrollbar(hex_mid, orient="vertical", command=self.hex_text.yview)
        self.hex_text.configure(xscroll=xsb.set, yscroll=ysb2.set)

        self.hex_text.pack(side="left", fill="both", expand=True)
        ysb2.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")

        # hex editor (selected range overwrite)
        hex_edit = ttk.LabelFrame(hexpane, text="Hex overwrite (in-place)")
        hex_edit.pack(fill="x", pady=(8, 0))

        row = ttk.Frame(hex_edit)
        row.pack(fill="x", padx=8, pady=6)

        ttk.Label(row, text="Target:").pack(side="left")
        self.hex_target_var = tk.StringVar(value="(none)")
        ttk.Label(row, textvariable=self.hex_target_var).pack(side="left", padx=(6, 16))

        ttk.Label(row, text="Bytes (space-separated hex):").pack(side="left")
        self.hex_edit_var = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.hex_edit_var, width=60).pack(side="left", padx=6)

        self.hex_apply_btn = ttk.Button(row, text="Overwrite", command=self.apply_hex_overwrite, state="disabled")
        self.hex_apply_btn.pack(side="left", padx=6)

        self.hex_revert_btn = ttk.Button(row, text="Revert bytes", command=self.revert_hex_overwrite, state="disabled")
        self.hex_revert_btn.pack(side="left", padx=6)

        # byte range tracked for hex overwrite
        self._hex_sel_start: Optional[int] = None
        self._hex_sel_len: Optional[int] = None

    # -----------------------------
    # File actions
    # -----------------------------
    def open_file(self):
        path = filedialog.askopenfilename(
            title="Open CDFbin",
            filetypes=[("CDFbin files", "*.cdf"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except Exception as e:
            messagebox.showerror("Open failed", str(e))
            return

        self.file_path = path
        self.original_blob = blob
        self.working_blob = blob
        chk = check_byte_count_registers(self.working_blob)
        if not chk.ok:
            msg = "Byte Count Registers check failed:\n\n"
            msg += "\n".join("• " + p for p in chk.problems)
            if chk.suggested:
                msg += "\n\nSuggested header repair:\n"
                for k, v in chk.suggested.items():
                    msg += f"  {k}: {chk.regs.get(k)} -> {v}\n"
                if messagebox.askyesno("Bad CDF header", msg + "\nApply repair now?"):
                    self.working_blob = apply_byte_count_fix(self.working_blob, chk.suggested)
            else:
                messagebox.showwarning("Bad CDF header", msg + "\n\nNo safe automatic repair was determined.")

        self.edits.clear()

        self.refresh_parse()

        self._file_menu.entryconfig("Save", state="normal")
        self._file_menu.entryconfig("Save As…", state="normal")
        self._tools_menu.entryconfig("Re-parse (refresh view)", state="normal")
        self._tools_menu.entryconfig("Discard unsaved edits", state="normal")

        self.hex_anchor = 0
        self._refresh_hex_view()

    def save_file(self):
        if not self.file_path or self.working_blob is None:
            return
        try:
            with open(self.file_path, "wb") as f:
                f.write(self.working_blob)
        except Exception as e:
            messagebox.showerror("Save failed", str(e))
            return
        messagebox.showinfo("Saved", "File saved successfully.")

    def save_file_as(self):
        if self.working_blob is None:
            return

        # ---- Byte count register sanity check before save ----
        chk = check_byte_count_registers(self.working_blob)
        if not chk.ok:
            msg = "Byte Count Registers check failed:\n\n"
            msg += "\n".join("• " + p for p in chk.problems)

            if chk.suggested:
                msg += "\n\nSuggested header repair:\n"
                for k, v in chk.suggested.items():
                    old = chk.regs.get(k)
                    msg += f"  {k}: {old} → {v}\n"

                if messagebox.askyesno(
                    "Invalid CDF header",
                    msg + "\nApply repair before saving?"
                ):
                    try:
                        self.working_blob = apply_byte_count_fix(
                            self.working_blob, chk.suggested
                        )
                    except Exception as e:
                        messagebox.showerror(
                            "Header repair failed",
                            str(e)
                        )
                        return
            else:
                messagebox.showwarning(
                    "Invalid CDF header",
                    msg + "\n\nNo safe automatic repair could be determined.\n"
                          "File will not be saved."
                )
                return
        # ------------------------------------------------------

        path = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=".cdfbin",
            filetypes=[("CDFbin files", "*.cdf"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "wb") as f:
                f.write(self.working_blob)
        except Exception as e:
            messagebox.showerror("Save As failed", str(e))
            return

        self.file_path = path
        messagebox.showinfo("Saved", "File saved successfully.")


    def discard_edits(self):
        if self.original_blob is None:
            return
        if not messagebox.askyesno("Discard edits", "Discard ALL unsaved edits and revert to file state at open?"):
            return
        self.working_blob = self.original_blob
        self.edits.clear()
        self.refresh_parse()
        self._refresh_hex_view()

    # -----------------------------
    # Parsing & tree
    # -----------------------------
    def refresh_parse(self):
        if self.working_blob is None:
            return
        try:
            self.instances = parse_cdfbin(self.working_blob, CDF_DEFS)
        except Exception as e:
            messagebox.showerror("Parse failed", str(e))
            return

        found = len(self.instances)
        self.status_var.set(
            f"Loaded: {self.file_path or '(unsaved)'} | Found {found} field instances | Edits: {len(self.edits)}"
        )
        self._rebuild_tree()
        self._rebuild_known_ranges()


        # clear selection/editor
        self._selected_instance = None
        self.sel_title.set("(none)")
        self._set_meta("")
        self._rebuild_editor(None)

        # hex selection cleared
        self._set_hex_target(None, None, label="(none)")

    def _rebuild_tree(self):
        self.tree.delete(*self.tree.get_children())
        filter_txt = self.filter_var.get().strip().lower()

        sections: Dict[str, List[CdfFieldInstance]] = {}
        for inst in self.instances:
            label = f"{inst.definition.name} #{inst.occurrence}"
            if filter_txt:
                if filter_txt not in inst.definition.section.lower() and filter_txt not in inst.definition.name.lower():
                    if filter_txt not in label.lower():
                        continue
            sections.setdefault(inst.definition.section, []).append(inst)

        # map iid -> key
        self.tree._cdf_key_map = {}
        self._cdf_iid_by_key.clear()


        for section in sorted(sections.keys()):
            sid = self.tree.insert("", "end", text=section, open=True)
            for inst in sections[section]:
                marker_hex = inst.definition.marker.hex(" ")
                key = (inst.definition.section, inst.definition.name, marker_hex, inst.occurrence)

                shown_val = self.edits.get(key, inst.value)
                val_str = self._format_value(shown_val, inst.definition.layout)
                typ_str = ",".join(inst.definition.layout) if inst.definition.layout else "(none)"
                off_str = f"{inst.offset_value:#x}"

                iid = self.tree.insert(
                    sid, "end",
                    text=f"{inst.definition.name} #{inst.occurrence}",
                    values=(val_str, typ_str, off_str)
                )
                self.tree._cdf_key_map[iid] = key
                self._cdf_iid_by_key[key] = iid


    def _on_select(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]

        key_map = getattr(self.tree, "_cdf_key_map", {})
        if iid not in key_map:
            self._selected_instance = None
            self.sel_title.set("(section)")
            self._set_meta("")
            self._rebuild_editor(None)
            self._highlight_selected_in_hex(None)
            return

        key = key_map[iid]
        inst = self._find_instance_by_key(key)
        if not inst:
            self._selected_instance = None
            self.sel_title.set("(not found)")
            self._set_meta("")
            self._rebuild_editor(None)
            self._highlight_selected_in_hex(None)
            return

        self._selected_instance = inst
        self.sel_title.set(f"{inst.definition.section} / {inst.definition.name} #{inst.occurrence}")

        marker_hex = inst.definition.marker.hex(" ")
        current = self.edits.get((inst.definition.section, inst.definition.name, marker_hex, inst.occurrence), inst.value)

        meta = (
            f"Marker: [{marker_hex}]\n"
            f"Marker offset: {inst.offset_marker:#x}\n"
            f"Value offset:  {inst.offset_value:#x}\n"
            f"Layout:        {inst.definition.layout}\n"
            f"Raw bytes:     {inst.raw_value_bytes.hex(' ')}\n"
            f"Current value: {current}\n"
        )
        if inst.definition.notes:
            meta += f"\nDoc note: {inst.definition.notes}\n"
        self._set_meta(meta)
        self._rebuild_editor(inst, current)

        # Jump hex view and highlight marker+payload
        self._highlight_selected_in_hex(inst)

    def _find_instance_by_key(self, key: Tuple[str, str, str, int]) -> Optional[CdfFieldInstance]:
        section, name, marker_hex, occ = key
        marker = bytes.fromhex(marker_hex)
        for inst in self.instances:
            if inst.definition.section == section and inst.definition.name == name and inst.definition.marker == marker and inst.occurrence == occ:
                return inst
        return None

    # -----------------------------
    # Scalar editor
    # -----------------------------
    def _rebuild_editor(self, inst: Optional[CdfFieldInstance], current_value: Optional[Tuple[Any, ...]] = None):
        for child in self.editor_frame.winfo_children():
            child.destroy()
        self._editor_vars.clear()

        if inst is None:
            self.apply_btn.configure(state="disabled")
            self.revert_btn.configure(state="disabled")
            return

        layout = inst.definition.layout
        if current_value is None:
            current_value = inst.value

        if not layout:
            ttk.Label(self.editor_frame, text="This field has no payload (layout=()). In-place editing not supported here.").pack(anchor="w")
            self.apply_btn.configure(state="disabled")
            self.revert_btn.configure(state="disabled")
            return

        grid = ttk.Frame(self.editor_frame)
        grid.pack(fill="x")

        for i, (t, v) in enumerate(zip(layout, current_value)):
            ttk.Label(grid, text=f"Value {i} ({t}):").grid(row=i, column=0, sticky="w", pady=3)

            sv = tk.StringVar(value=self._stringify_scalar(v, t))
            self._editor_vars.append(sv)

            e = ttk.Entry(grid, textvariable=sv, width=26)
            e.grid(row=i, column=1, sticky="w", padx=(8, 0), pady=3)

        self.apply_btn.configure(state="normal")
        self.revert_btn.configure(state="normal")

    def _stringify_scalar(self, v: Any, t: Scalar) -> str:
        if t == "float":
            return f"{float(v):.6g}"
        return str(int(v))

    def apply_edit(self):
        inst = self._selected_instance
        if inst is None or self.working_blob is None:
            return

        marker_hex = inst.definition.marker.hex(" ")
        key = (inst.definition.section, inst.definition.name, marker_hex, inst.occurrence)

        try:
            new_values = self._parse_editor_values(inst.definition.layout, self._editor_vars)
            new_raw = encode_payload(inst.definition.layout, new_values)
            if len(new_raw) != len(inst.raw_value_bytes):
                raise ValueError("Edit would change payload size (not allowed in-place).")

            out = bytearray(self.working_blob)
            start = inst.offset_value
            out[start:start+len(new_raw)] = new_raw
            self.working_blob = bytes(out)
            self.edits[key] = new_values

        except Exception as e:
            messagebox.showerror("Invalid edit", str(e))
            return

        self.refresh_parse()
        self._refresh_hex_view()
        messagebox.showinfo("Applied", "Edit applied (in-place).")

    def revert_field(self):
        inst = self._selected_instance
        if inst is None or self.original_blob is None or self.working_blob is None:
            return

        marker_hex = inst.definition.marker.hex(" ")
        key = (inst.definition.section, inst.definition.name, marker_hex, inst.occurrence)
        if key not in self.edits:
            return

        try:
            orig_instances = parse_cdfbin(self.original_blob, [inst.definition])
            match = next((oi for oi in orig_instances if oi.occurrence == inst.occurrence), None)
            if match is None:
                raise ValueError("Could not locate original instance to revert.")

            out = bytearray(self.working_blob)
            out[inst.offset_value:inst.offset_value+len(inst.raw_value_bytes)] = match.raw_value_bytes
            self.working_blob = bytes(out)

            del self.edits[key]
        except Exception as e:
            messagebox.showerror("Revert failed", str(e))
            return

        self.refresh_parse()
        self._refresh_hex_view()

    def _parse_editor_values(self, layout: Tuple[Scalar, ...], vars_: List[tk.StringVar]) -> Tuple[Any, ...]:
        if len(layout) != len(vars_):
            raise ValueError("Internal editor mismatch")
        out: List[Any] = []
        for t, sv in zip(layout, vars_):
            s = sv.get().strip()
            if t == "float":
                out.append(float(s))
            else:
                n = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
                if t == "byte" and not (0 <= n <= 255):
                    raise ValueError(f"byte out of range: {n}")
                out.append(n)
        return tuple(out)

    def _format_value(self, value: Tuple[Any, ...], layout: Tuple[Scalar, ...]) -> str:
        if not layout:
            return "(marker only)"
        parts = []
        for v, t in zip(value, layout):
            if t == "float":
                parts.append(f"{float(v):.6g}")
            else:
                parts.append(str(int(v)))
        return parts[0] if len(parts) == 1 else "(" + ", ".join(parts) + ")"

    def _set_meta(self, s: str):
        self.meta_text.configure(state="normal")
        self.meta_text.delete("1.0", "end")
        self.meta_text.insert("1.0", s)
        self.meta_text.configure(state="disabled")

    # -----------------------------
    # Hex viewer/editor
    # -----------------------------
    def _refresh_hex_view(self):
        if self.working_blob is None:
            self._set_hex_text("")
            self.hex_info_var.set("")
            return

        blob = self.working_blob
        # align anchor to 16 bytes
        self.hex_anchor = (self.hex_anchor // 16) * 16
        self.hex_anchor = clamp(self.hex_anchor, 0, max(0, len(blob) - 1))

        lines = format_hex_lines(blob, self.hex_anchor, self.hex_bytes_per_page, 16)
        self._hex_line_index.clear()
        # build an index: line start offset -> line number within this view
        for idx, line in enumerate(lines):
            # each line starts with 8 hex digits offset
            off = int(line.split()[0], 16)
            self._hex_line_index[off] = idx

        self._set_hex_text("\n".join(lines) + ("\n" if lines else ""))

        end = min(len(blob), self.hex_anchor + self.hex_bytes_per_page)
        self.hex_info_var.set(f"{self.hex_anchor:08X} .. {end:08X}  (size {len(blob)} bytes)")

        # re-highlight selection if any
        self._highlight_selected_in_hex(self._selected_instance, refresh_only=True)

    def _set_hex_text(self, s: str):
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        self.hex_text.insert("1.0", s)
        self.hex_text.configure(state="disabled")

    def hex_page(self, direction: int):
        if self.working_blob is None:
            return
        self.hex_anchor += direction * self.hex_bytes_per_page
        self.hex_anchor = clamp(self.hex_anchor, 0, max(0, len(self.working_blob) - 1))
        self._refresh_hex_view()

    def hex_jump(self):
        if self.working_blob is None:
            return
        s = self.jump_var.get().strip()
        try:
            off = int(s, 16) if s.lower().startswith("0x") else int(s, 16)
        except Exception:
            messagebox.showerror("Jump failed", "Enter a hex offset like 0x1A2B or 1A2B.")
            return
        off = clamp(off, 0, max(0, len(self.working_blob) - 1))
        self.hex_anchor = (off // 16) * 16
        self._refresh_hex_view()

    def _highlight_selected_in_hex(self, inst: Optional[CdfFieldInstance], refresh_only: bool = False):
        # clear old tags
        self.hex_text.configure(state="normal")
        self.hex_text.tag_remove("sel_marker", "1.0", "end")
        self.hex_text.tag_remove("sel_value", "1.0", "end")
        self.hex_text.tag_remove("sel_both", "1.0", "end")
        self.hex_text.configure(state="disabled")

        if inst is None or self.working_blob is None:
            if not refresh_only:
                self._set_hex_target(None, None, label="(none)")
            return

        marker_start = inst.offset_marker
        marker_len = len(inst.definition.marker)
        value_start = inst.offset_value
        value_len = len(inst.raw_value_bytes)

        # decide if we should jump view (unless refresh_only)
        if not refresh_only:
            focus = marker_start
            self.hex_anchor = (focus // 16) * 16
            # show a little context above if possible
            self.hex_anchor = clamp(self.hex_anchor - 16 * 4, 0, max(0, len(self.working_blob) - 1))
            self._refresh_hex_view()  # this will call back into highlight with refresh_only=True, so guard:
            # after refresh, we’ll tag below as well.
            # (refresh_only is false here so we continue)

        # set target for hex overwrite: default to payload (value bytes)
        self._set_hex_target(value_start, value_len,
                             label=f"{inst.definition.name} #{inst.occurrence} payload @ {value_start:08X} ({value_len} bytes)")
        # also fill edit box with current payload hex
        payload = self.working_blob[value_start:value_start+value_len]
        self.hex_edit_var.set(payload.hex(" ").upper())

        # tag marker and payload in visible hex view
        self._tag_range_in_hex(marker_start, marker_len, "sel_marker")
        self._tag_range_in_hex(value_start, value_len, "sel_value")

        # scroll into view (to marker line)
        self._see_offset(marker_start)

    def _see_offset(self, off: int):
        # best-effort: scroll to the line that includes 'off'
        line_off = (off // 16) * 16
        idx = self._hex_line_index.get(line_off)
        if idx is None:
            return
        # Tk text index is 1-based lines
        self.hex_text.configure(state="normal")
        self.hex_text.see(f"{idx+1}.0")
        self.hex_text.configure(state="disabled")

    def _tag_range_in_hex(self, start: int, length: int, tag: str):
        if self.working_blob is None:
            return
        if length <= 0:
            return

        # only tag bytes that are currently visible in this hex page
        page_start = self.hex_anchor
        page_end = self.hex_anchor + self.hex_bytes_per_page

        sel_start = max(start, page_start)
        sel_end = min(start + length, page_end)
        if sel_end <= sel_start:
            return

        # mapping from byte offset in line to character position in our rendered line:
        # "00000000␠␠" (10 chars incl 2 spaces) + hex area (16*3-1 chars) + "␠␠|" + ascii + "|"
        # For byte i (0..15): hex starts at col 10 + i*3, two chars wide.
        def hex_col(byte_i: int) -> int:
            return 10 + byte_i * 3

        self.hex_text.configure(state="normal")
        for off in range(sel_start, sel_end):
            line_off = (off // 16) * 16
            byte_i = off - line_off
            line_idx = self._hex_line_index.get(line_off)
            if line_idx is None:
                continue
            line_no = line_idx + 1

            c0 = hex_col(byte_i)
            c1 = c0 + 2
            self.hex_text.tag_add(tag, f"{line_no}.{c0}", f"{line_no}.{c1}")
        self.hex_text.configure(state="disabled")

    def _set_hex_target(self, start: Optional[int], length: Optional[int], label: str):
        self._hex_sel_start = start
        self._hex_sel_len = length
        self.hex_target_var.set(label)
        if start is None or length is None or self.working_blob is None:
            self.hex_apply_btn.configure(state="disabled")
            self.hex_revert_btn.configure(state="disabled")
        else:
            self.hex_apply_btn.configure(state="normal")
            self.hex_revert_btn.configure(state="normal")

    def _parse_hex_bytes(self, s: str) -> bytes:
        s = s.strip()
        if not s:
            return b""
        parts = s.replace(",", " ").split()
        try:
            return bytes(int(p, 16) for p in parts)
        except Exception:
            raise ValueError("Hex bytes must be like: 'DE AD BE EF' (space-separated)")

    def apply_hex_overwrite(self):
        if self.working_blob is None:
            return
        if self._hex_sel_start is None or self._hex_sel_len is None:
            return

        start = self._hex_sel_start
        n = self._hex_sel_len
        try:
            new_bytes = self._parse_hex_bytes(self.hex_edit_var.get())
        except Exception as e:
            messagebox.showerror("Hex overwrite failed", str(e))
            return

        if len(new_bytes) != n:
            messagebox.showerror(
                "Hex overwrite failed",
                f"Byte count mismatch: target is {n} bytes but you provided {len(new_bytes)} bytes.\n"
                "In-place overwrite must be the same length."
            )
            return

        # apply
        out = bytearray(self.working_blob)
        out[start:start+n] = new_bytes
        self.working_blob = bytes(out)

        # After raw edits, re-parse definitions (some markers may change if you edit them)
        self.refresh_parse()
        self._refresh_hex_view()
        messagebox.showinfo("Overwritten", f"Wrote {n} bytes at {start:08X} (in-place).")

    def revert_hex_overwrite(self):
        if self.original_blob is None or self.working_blob is None:
            return
        if self._hex_sel_start is None or self._hex_sel_len is None:
            return

        start = self._hex_sel_start
        n = self._hex_sel_len
        if start + n > len(self.original_blob):
            messagebox.showerror("Revert failed", "Selected range is out of bounds of original file.")
            return

        out = bytearray(self.working_blob)
        out[start:start+n] = self.original_blob[start:start+n]
        self.working_blob = bytes(out)

        self.refresh_parse()
        self._refresh_hex_view()
        messagebox.showinfo("Reverted", f"Reverted {n} bytes at {start:08X} to original.")
    
    def _rebuild_known_ranges(self):
        """Build [start,end) ranges for every known marker/payload so hex clicks can resolve to a tree item."""
        self._known_ranges.clear()
        for inst in self.instances:
            marker_hex = inst.definition.marker.hex(" ")
            key = (inst.definition.section, inst.definition.name, marker_hex, inst.occurrence)

            ms = inst.offset_marker
            ml = len(inst.definition.marker)
            if ml > 0:
                self._known_ranges.append((ms, ms + ml, key))

            vs = inst.offset_value
            vl = len(inst.raw_value_bytes)
            if vl > 0:
                self._known_ranges.append((vs, vs + vl, key))

        # sort by start to make scanning predictable
        self._known_ranges.sort(key=lambda r: r[0])

    def _hex_click_to_offset(self, event) -> Optional[int]:
        """
        Convert a click in the rendered hex dump into an absolute byte offset in the file,
        supporting both hex area and ASCII area clicks.
        """
        if self.working_blob is None:
            return None

        # Tk gives us a text index at pixel position
        idx = self.hex_text.index(f"@{event.x},{event.y}")  # like "12.34"
        try:
            line_str, col_str = idx.split(".")
            line_no = int(line_str)
            col = int(col_str)
        except Exception:
            return None

        # Get the full line text and parse the left offset ("00000000")
        line_text = self.hex_text.get(f"{line_no}.0", f"{line_no}.end")
        if not line_text.strip():
            return None

        parts = line_text.split()
        if not parts:
            return None

        try:
            line_base_off = int(parts[0], 16)
        except Exception:
            return None

        # Layout geometry for rendered lines:
        # "00000000␠␠" -> 10 chars before hex bytes begin
        # hex bytes occupy 16*3-1 = 47 chars: "AA BB ...", bytes at col 10 + i*3 (2 chars each)
        # then "  |" (3 chars)
        # then 16 ASCII chars
        hex_start = 10
        hex_width = 16 * 3 - 1  # 47
        hex_end = hex_start + hex_width  # exclusive-ish boundary for our checks

        ascii_start = hex_end + 3  # two spaces + '|' => "  |"
        ascii_end = ascii_start + 16

        # clicked in hex area?
        if hex_start <= col < hex_end:
            rel = col - hex_start
            byte_i = rel // 3
            within_triplet = rel % 3
            # only accept if on the actual hex digits, not the separating space
            if byte_i < 0 or byte_i > 15:
                return None
            if within_triplet == 2:
                return None  # clicked the space between bytes
            off = line_base_off + byte_i
            if 0 <= off < len(self.working_blob):
                return off
            return None

        # clicked in ASCII area?
        if ascii_start <= col < ascii_end:
            byte_i = col - ascii_start
            if 0 <= byte_i < 16:
                off = line_base_off + byte_i
                if 0 <= off < len(self.working_blob):
                    return off
            return None

        return None

    def _find_key_for_offset(self, off: int) -> Optional[Tuple[str, str, str, int]]:
        """Return the instance key if 'off' falls within any known marker/payload range."""
        for start, end, key in self._known_ranges:
            if start <= off < end:
                return key
        return None

    def _on_hex_click(self, event):
        """
        If the clicked byte belongs to a known (definition-derived) state,
        select the corresponding node in the tree.
        """
        off = self._hex_click_to_offset(event)
        if off is None:
            return

        key = self._find_key_for_offset(off)
        if key is None:
            return  # clicked an unknown region; do nothing

        iid = self._cdf_iid_by_key.get(key)
        if not iid:
            return

        # Select and scroll tree; this will trigger <<TreeviewSelect>> and reuse existing logic
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        self.tree.see(iid)


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    app = CdfEditorApp()
    app.mainloop()
