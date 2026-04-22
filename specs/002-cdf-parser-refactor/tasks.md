# Tasks: CDF Parser XML Refactor

## Phase 1: Setup
- [x] T001 Initialize `tests/` directory and configure standard `unittest` framework runner.
- [x] T002 [P] Extract hardcoded `CDF_DEFS` from `cdf_editorV0.2.py` into a reference backup `cdf_defs_legacy.py` to allow clean assertions against the new parser.

## Phase 2: Core XML Parser (User Story 1 - Modding a Chassis File)
*Goal: Dynamically load the `cdf-hex-map.xml` file to produce `CdfFieldDef` structures, fully decoupled from the UI.*

- [x] T003 [US1] [P] (TDD) Create `tests/test_cdf_parser.py` and write failing unit tests for `load_dictionary()`. Ensure it asserts the `sys._MEIPASS` fallback logic and correct parsing of `group` and `notes` elements.
- [x] T004 [US1] Create `cdf_parser.py`. Port core functions (`decode_payload`, `encode_payload`, `parse_cdfbin`) and `CdfFieldDef` dataclass from V0.2.
- [x] T005 [US1] Implement `load_dictionary()` in `cdf_parser.py` to parse `cdf-hex-map.xml` and pass all T003 tests.

## Phase 3: GUI Application & TreeView (User Story 1 & 2)
*Goal: Instantiate the Tkinter GUI, build the nested Section->Group->Block TreeView, and display translation notes on selection.*

- [x] T006 [US1] (TDD) Create `tests/test_cdf_editor_gui.py` to assert the presence of core UI elements (Treeview, Notes Text Widget, Search Entry).
- [x] T007 [US1] Create `cdf_editor_gui.py`. Setup basic Tkinter Application class `CdfEditorApp`, wrapping the new `cdf_parser.py` engine.
- [x] T008 [US1] Implement the hierarchical TreeView rendering logic in `build_tree()`.
- [x] T009 [US2] Implement the `<<TreeviewSelect>>` event handler to populate the right-hand "Translation Notes" text widget.
- [x] T010 [US1] [P] Implement the `on_key_release` event for the live Filter Bar, adding logic to detach non-matching nodes or rebuild the tree.

## Phase 4: Menu & Custom XML (Clarification 2)
*Goal: Allow advanced users to load custom XML files for the current session only.*

- [x] T011 [US2] (TDD) Write a test in `test_cdf_editor_gui.py` validating the custom dictionary load triggers a full TreeView rebuild.
- [x] T012 [US2] Implement `load_custom_dictionary()` in `cdf_editor_gui.py` connecting the `filedialog` to the parser and UI rebuild.

## Phase 5: Polish & Deletion
- [x] T013 Verify the in-place hex modification payload logic correctly integrates with the UI popup windows in `cdf_editor_gui.py`.
- [x] T014 Delete the deprecated `cdf_editorV0.2.py`.

---
## Implementation Strategy
1. **Tests First**: All parser and UI integration logic will have failing tests written first, mapping directly to our requirements.
2. **Parser Decoupling**: Isolate `cdf_parser.py` entirely from Tkinter so it is purely deterministic and easily testable.
3. **UI Replacement**: Develop `cdf_editor_gui.py` iteratively alongside the tests.
