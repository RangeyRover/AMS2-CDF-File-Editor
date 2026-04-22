# Implementation Plan: CDF Parser XML Refactor

## 1. Technical Context
- **Language/Framework**: Python 3.8+
- **UI Framework**: `tkinter` + `ttk`
- **Data Source**: `cdf-hex-map.xml`
- **Packaging**: PyInstaller `--onefile`

## 2. Phase 0: Research & Architecture
**Unknowns Addressed**:
- *How to reliably access bundled files in PyInstaller?*
  **Decision**: Use `sys._MEIPASS`.
  **Rationale**: When packaged with `--onefile`, PyInstaller extracts bundled files to a temporary folder (`sys._MEIPASS`). We will wrap the XML loading logic in a helper function `get_resource_path()` that checks for `sys._MEIPASS` or falls back to the local directory (for development).

- *How to implement a live filter on a Tkinter TreeView?*
  **Decision**: The `ttk.Treeview` does not natively support "hiding" nodes. We must detach (`tree.detach(item)`) non-matching nodes or clear and rebuild the tree from a cached hierarchical data structure.
  **Rationale**: Clearing and rebuilding is cleaner but slower. Given ~500 items, clearing and re-inserting matching nodes is practically instantaneous in Tkinter. We will maintain an in-memory dictionary of the full hierarchy and rapidly rebuild the tree on keystrokes (`<KeyRelease>`).

## 3. Phase 1: Data Model & Contracts

### 3.1 Data Model (`cdf_parser.py`)
```python
@dataclass(frozen=True)
class CdfFieldDef:
    name: str
    section: str
    group: str           # NEW: Extracted from XML hierarchy
    marker: bytes
    layout: Tuple[Scalar, ...]
    notes: str = ""      # NEW: Extracted from <notes> tags
    optional: bool = True
    repeatable: bool = True
```

### 3.2 Internal Contracts

**`cdf_parser.py`**
- `load_dictionary(xml_path: str = None) -> List[CdfFieldDef]`
  - Parses `cdf-hex-map.xml`. If `xml_path` is None, loads the bundled default.
- `parse_cdfbin(blob: bytes, defs: List[CdfFieldDef]) -> List[CdfFieldInstance]`
  - (Existing function) Unchanged core logic, but now consumes dynamically loaded defs.

**`cdf_editor_gui.py`**
- `class CdfEditorApp(tk.Tk):`
  - `def __init__(self):` Initializes UI, loads `cdf_parser.load_dictionary()`.
  - `def build_tree(self, filter_text=""):` Rebuilds the TreeView, filtering by `filter_text`.
  - `def on_tree_select(self, event):` Updates the new "Notes Panel" with the selected `CdfFieldDef.notes`.
  - `def load_custom_dictionary(self):` Opens a file dialog, updates the dictionary, and calls `build_tree()`.

## 4. Execution Phases (Handoff to speckit.tasks)
1. Split `cdf_editorV0.2.py` into `cdf_parser.py` and `cdf_editor_gui.py`.
2. Implement `load_dictionary()` in `cdf_parser.py`.
3. Refactor the Tkinter UI to add the Notes Panel and the live filter bar.
4. Update TreeView logic to render hierarchies (`Section -> Group -> Block`).
5. Wire up the "Load Custom Dictionary" menu item.
6. Verify against `chassis.cdfbin`.
