from typing import List, Tuple, Literal
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
    # POWER / AI 
    # =========================
    CdfFieldDef("BodyDragBase_Int32",      "BODY AERO", hx("21 67 0B 57 AB"), ("int32",), "BodyDragBase (int32?) e.g. 1200 (orig 1380)"),
    CdfFieldDef("HorsepowerMultiplier",    "ENGINE",    hx("22 A3 BF 1E 60"), ("float",), "hp multi"),
    CdfFieldDef("GeneralPowerMult",        "ENGINE",    hx("22 C3 66 7D 2E"), ("float",), "GeneralPowerMult (torque multiplier?)"),
    CdfFieldDef("AISpeedParam",            "AI",        hx("22 8C 23 4A AB"), ("float",), "AI speed/start-line param? (repeatable)"),
    CdfFieldDef("AISpeedTriplet",          "AI",        hx("24 F1 5E D9 7A A3 02"), ("float","float","float"), "AI speed triplet (f,f,f)"),

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
    # DRIVELINE 
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

    # -------------------------
    # GEARS
    # -------------------------
    CdfFieldDef("FinalDriveSetting",       "DRIVELINE", hx("20 C1 EB DC 28"), ("byte",), "FinalDriveSetting={byte}"),
    CdfFieldDef("ReverseGearSetting",      "DRIVELINE", hx("28 D6 71 85 B0"), ("byte",), "ReverseGearSetting={byte} (often 0)"),
    CdfFieldDef("ForwardGears",            "DRIVELINE", hx("20 FF 0C 22 07"), ("byte",), "ForwardGears={byte}"),
    CdfFieldDef("GearOneSetting",          "DRIVELINE", hx("28 F4 CC 2F 1D"), ("byte",), "GearOneSetting={byte}"),
    CdfFieldDef("GearTwoSetting",          "DRIVELINE", hx("20 8D 69 C2 DA"), ("byte",), "GearTwoSetting={byte}"),
    CdfFieldDef("GearThreeSetting",        "DRIVELINE", hx("20 C0 25 93 C3"), ("byte",), "GearThreeSetting={byte}"),
    CdfFieldDef("GearFourSetting",         "DRIVELINE", hx("20 78 92 B7 5A"), ("byte",), "GearFourSetting={byte}"),
    CdfFieldDef("GearFiveSetting",         "DRIVELINE", hx("20 78 4E 48 36"), ("byte",), "GearFiveSetting={byte}"),
    CdfFieldDef("GearSixSetting",          "DRIVELINE", hx("20 5F 2B A9 EE"), ("byte",), "GearSixSetting={byte}"),
    CdfFieldDef("GearSevenSetting",        "DRIVELINE", hx("20 49 EE 13 F6"), ("byte",), "GearSevenSetting={byte}"),
]
