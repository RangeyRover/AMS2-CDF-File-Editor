import struct
from typing import Any, Dict, List, Literal, Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cdf_parser
from cdf_parser import CdfFieldDef, CdfFieldInstance, check_byte_count_registers, apply_byte_count_fix, parse_cdfbin, Scalar

try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

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

def clamp(val, min_val, max_val):
    return max(min_val, min(val, max_val))

class CdfEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CDFbin Editor v0.3.2")
        self.geometry("1400x820")

        self.file_path: Optional[str] = None
        self.original_blob: Optional[bytes] = None
        self.working_blob: Optional[bytes] = None
        self.instances: List[CdfFieldInstance] = []
        self.cdf_defs: List[CdfFieldDef] = []
        
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
        fm.add_command(label="Load Custom cdf-hex-map.xml...", command=self.load_custom_dictionary)
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
        self._tools_menu = tm
        self._file_menu = fm

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
        style.configure("Treeview", rowheight=28)  # tweak 24–34 to taste     

        ttk.Label(topbar, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._rebuild_tree())
        self.search_entry = ttk.Entry(topbar, textvariable=self.search_var, width=40)
        self.search_entry.pack(side="left", padx=6)
        
        # Keep old filter_var mapped so the rest of the code works
        self.filter_var = self.search_var

        self.status_var = tk.StringVar(value="Open a .cdf or .cdfbin to begin.")
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

        ttk.Label(right, text="Translation Notes", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.notes_text = tk.Text(right, height=8, wrap="word")
        self.notes_text.insert("1.0", "Hex pane instructions...\\n")
        self.notes_text.configure(state="disabled")
        self.notes_text.pack(fill="both", expand=True)
        # Keep backward compat
        self.notes = self.notes_text

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

    def load_dictionary(self, xml_path=None):
        try:
            self.cdf_defs = cdf_parser.load_dictionary(xml_path)
            self.status_var.set(f"Dictionary loaded with {len(self.cdf_defs)} definitions. Open a .cdf or .cdfbin to begin.")
            if xml_path:
                self.title(f"CDFbin Editor v0.3.2 - Custom Dictionary: {xml_path}")
            else:
                self.title("CDFbin Editor v0.3.2")
        except Exception as e:
            self.status_var.set(f"Dictionary failed to load: {e}")
            messagebox.showerror("Dictionary Error", f"Failed to load XML dictionary:\n{e}")
        if self.working_blob:
            self.refresh_parse()

    def load_custom_dictionary(self):
        path = filedialog.askopenfilename(
            title="Load Custom Dictionary",
            filetypes=[("XML map", "*.xml"), ("All files", "*.*")]
        )
        if path:
            self.load_dictionary(path)
    # -----------------------------
    # File actions
    # -----------------------------
    def open_file(self):
        path = filedialog.askopenfilename(
            title="Open CDF / CDFbin",
            filetypes=[("CDF files", "*.cdf *.cdfbin"), ("CDFbin files", "*.cdfbin"), ("CDF files", "*.cdf"), ("All files", "*.*")]
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
            filetypes=[("CDF files", "*.cdf *.cdfbin"), ("CDFbin files", "*.cdfbin"), ("CDF files", "*.cdf"), ("All files", "*.*")]
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
            self.instances = parse_cdfbin(self.working_blob, self.cdf_defs)
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

        # Hierarchy: section -> group -> inst
        sections: Dict[str, Dict[str, List[CdfFieldInstance]]] = {}
        for inst in self.instances:
            label = f"{inst.definition.name} #{inst.occurrence}"
            match = False
            if not filter_txt:
                match = True
            elif filter_txt in inst.definition.section.lower() or \
                 filter_txt in inst.definition.group.lower() or \
                 filter_txt in inst.definition.name.lower() or \
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
            new_raw = cdf_parser.encode_payload(inst.definition.layout, new_values)
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
if __name__ == '__main__':
    app = CdfEditorApp()
    app.load_dictionary()
    app.mainloop()
