import re
import sys

with open('cdf_editorV0.2.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Remove everything from "Scalar = Literal[" down to "CDF_DEFS: List[CdfFieldDef] = ["
# We need to preserve the imports at the top
imports = """import struct
from typing import Any, Dict, List, Literal, Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cdf_parser
from cdf_parser import CdfFieldDef, CdfFieldInstance, check_byte_count_registers, apply_byte_count_fix, parse_cdfbin

try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass
"""

# Extract everything from class CdfEditorApp to end of file
app_match = re.search(r'class CdfEditorApp\(tk\.Tk\):.*', text, re.DOTALL)
if not app_match:
    print("Could not find CdfEditorApp")
    sys.exit(1)

app_code = app_match.group(0)

# 2. Modify app_code: `self.instances = parse_cdfbin(self.working_blob, CDF_DEFS)`
# -> `self.instances = cdf_parser.parse_cdfbin(self.working_blob, self.cdf_defs)`
app_code = app_code.replace(
    'self.instances = parse_cdfbin(self.working_blob, CDF_DEFS)',
    'self.instances = parse_cdfbin(self.working_blob, self.cdf_defs)'
)

# Replace TreeView initialisation & search field
# In _build_layout(self):
#    ttk.Label(topbar, text="Filter:").pack(side="left")
#    self.filter_var = tk.StringVar()

# Add `load_dictionary()` to init
init_replace = """    def __init__(self):
        super().__init__()
        self.title("CDFbin Editor")
        self.geometry("1400x820")

        self.file_path: Optional[str] = None
        self.original_blob: Optional[bytes] = None
        self.working_blob: Optional[bytes] = None
        self.instances: List[CdfFieldInstance] = []
        self.cdf_defs: List[CdfFieldDef] = []
        
        self.edits: Dict[Tuple[str, str, str, int], Tuple[Any, ...]] = {}"""
app_code = re.sub(r'    def __init__\(self\):.*?self\.edits: Dict\[Tuple\[str, str, str, int\], Tuple\[Any, \.\.\.\]\] = \{\}', init_replace, app_code, flags=re.DOTALL)

# Modify _build_layout for Search Entry and _on_select for notes_text
# Note: original file has self.notes which is a tk.Text.
# In test_cdf_editor_gui.py, I asserted `self.app.notes_text`, `self.app.search_var`, `self.app.search_entry`

layout_repl = """        ttk.Label(topbar, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._rebuild_tree())
        self.search_entry = ttk.Entry(topbar, textvariable=self.search_var, width=40)
        self.search_entry.pack(side="left", padx=6)
        
        # Keep old filter_var mapped so the rest of the code works
        self.filter_var = self.search_var"""
app_code = re.sub(r'        ttk\.Label\(topbar, text="Filter:"\)\.pack\(side="left"\).*?ttk\.Entry\(topbar, textvariable=self\.filter_var, width=40\)\.pack\(side="left", padx=6\)', layout_repl, app_code, flags=re.DOTALL)

notes_repl = """        ttk.Label(right, text="Translation Notes", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.notes_text = tk.Text(right, height=8, wrap="word")
        self.notes_text.insert("1.0", "Hex pane instructions...\\n")
        self.notes_text.configure(state="disabled")
        self.notes_text.pack(fill="both", expand=True)
        # Keep backward compat
        self.notes = self.notes_text"""
app_code = re.sub(r'        ttk\.Label\(right, text="Notes / Help", font=\("Segoe UI", 10, "bold"\)\)\.pack\(anchor="w"\).*?self\.notes\.pack\(fill="both", expand=True\)', notes_repl, app_code, flags=re.DOTALL)

# Rebuild tree logic for section -> group -> block
tree_build = """    def _rebuild_tree(self):
        self.tree.delete(*self.tree.get_children())
        filter_txt = self.filter_var.get().strip().lower()

        # Hierarchy: section -> group -> inst
        sections: Dict[str, Dict[str, List[CdfFieldInstance]]] = {}
        for inst in self.instances:
            label = f"{inst.definition.name} #{inst.occurrence}"
            match = False
            if not filter_txt:
                match = True
            elif filter_txt in inst.definition.section.lower() or \\
                 filter_txt in inst.definition.group.lower() or \\
                 filter_txt in inst.definition.name.lower() or \\
                 filter_txt in label.lower():
                match = True
                
            if match:
                sec = inst.definition.section
                grp = getattr(inst.definition, 'group', 'General')
                if sec not in sections: sections[sec] = {}
                if grp not in sections[sec]: sections[sec][grp] = []
                sections[sec][grp].append(inst)

        self.tree._cdf_key_map = {}
        self._cdf_iid_by_key.clear()

        for section in sorted(sections.keys()):
            sid = self.tree.insert("", "end", text=section, open=(filter_txt != ""))
            for group in sorted(sections[section].keys()):
                gid = self.tree.insert(sid, "end", text=group, open=(filter_txt != ""))
                for inst in sections[section][group]:
                    marker_hex = inst.definition.marker.hex(" ")
                    key = (inst.definition.section, inst.definition.name, marker_hex, inst.occurrence)

                    shown_val = self.edits.get(key, inst.value)
                    val_str = self._format_value(shown_val, inst.definition.layout)
                    typ_str = ",".join(inst.definition.layout) if inst.definition.layout else "(none)"
                    off_str = f"{inst.offset_value:#x}"

                    iid = self.tree.insert(
                        gid, "end",
                        text=f"{inst.definition.name} #{inst.occurrence}",
                        values=(val_str, typ_str, off_str)
                    )
                    self.tree._cdf_key_map[iid] = key
                    self._cdf_iid_by_key[key] = iid"""
app_code = re.sub(r'    def _rebuild_tree\(self\):.*?self\._cdf_iid_by_key\[key\] = iid', tree_build, app_code, flags=re.DOTALL)

# Add load_dictionary method
methods_to_add = """    def load_dictionary(self, xml_path=None):
        self.cdf_defs = cdf_parser.load_dictionary(xml_path)
        if self.working_blob:
            self.refresh_parse()

    def load_custom_dictionary(self):
        path = filedialog.askopenfilename(
            title="Load Custom Dictionary",
            filetypes=[("XML map", "*.xml"), ("All files", "*.*")]
        )
        if path:
            self.load_dictionary(path)
"""
app_code = app_code.replace('    # -----------------------------', methods_to_add + '    # -----------------------------', 1)

# Add File -> Load Custom Dictionary
menu_repl = """        fm.add_command(label="Open…", command=self.open_file)
        fm.add_command(label="Load Custom XML Dictionary...", command=self.load_custom_dictionary)"""
app_code = app_code.replace('        fm.add_command(label="Open…", command=self.open_file)', menu_repl)


with open('cdf_editor_gui.py', 'w', encoding='utf-8') as f:
    f.write(imports + "\n" + app_code + "\n\nif __name__ == '__main__':\n    app = CdfEditorApp()\n    app.load_dictionary()\n    app.mainloop()\n")
