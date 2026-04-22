# Embed XML, GUI Override, and Release Packaging

This plan details the implementation of embedded XML packaging via PyInstaller, deliberate GUI-driven custom XML overrides, final XML dictionary polishing, and TDD validation.

## User Review Required

Please review the revised implementation details. The dynamic loading of XML from the working directory has been removed in favor of a deliberate "File -> Load Custom Dictionary" GUI action.

## Proposed Changes

---

### Phase 1: XML Final Polish
- Perform a manual review of the remaining 26 unknowns identified in the corpus scan.
- Attempt to classify, rename, or structure the remaining edge-case parameters (e.g. `PC2NewSection_*`, `ZeroMarker_28_*` boundaries) to ensure the `cdf-hex-map.xml` is as clean as possible for the release.

---

### Phase 2: Tests (TDD)

#### [NEW] [test_dict_loading.py](file:///c:/Users/markn/OneDrive%20-%20IXL%20Signalling/0-01%20AI%20Programming/AI%20Coding/AMS2_CDF_Editor/AMS2-CDF-File-Editor/tests/test_dict_loading.py)
- Create TDD test cases using `pytest` and `unittest.mock.patch`.
- **Tests to write:**
  - `test_embedded_loading`: When `xml_path` is omitted, the `load_dictionary` function correctly resolves to `sys._MEIPASS` when frozen, or the local source directory during development.
  - `test_explicit_loading`: `load_dictionary` respects a deliberately provided path.

#### [MODIFY] [test_cdf_editor_gui.py](file:///c:/Users/markn/OneDrive%20-%20IXL%20Signalling/0-01%20AI%20Programming/AI%20Coding/AMS2_CDF_Editor/AMS2-CDF-File-Editor/tests/test_cdf_editor_gui.py)
- Mock `tkinter.filedialog.askopenfilename`.
- Test that triggering the "Load Custom Dictionary" action correctly updates `self.defs` and re-parses the currently active `.cdf` file.

---

### Phase 3: Core Logic & GUI

#### [MODIFY] [cdf_parser.py](file:///c:/Users/markn/OneDrive%20-%20IXL%20Signalling/0-01%20AI%20Programming/AI%20Coding/AMS2_CDF_Editor/AMS2-CDF-File-Editor/cdf_parser.py)
- Simplify `load_dictionary`: It will no longer dynamically scan the working directory. It will only use an explicit `xml_path` if provided, otherwise it safely falls back to the embedded `_MEIPASS` resource or source tree location.

#### [MODIFY] [cdf_editor_gui.py](file:///c:/Users/markn/OneDrive%20-%20IXL%20Signalling/0-01%20AI%20Programming/AI%20Coding/AMS2_CDF_Editor/AMS2-CDF-File-Editor/cdf_editor_gui.py)
- Add a new cascade menu under `File` -> `Load Custom Dictionary...`.
- Implement `load_custom_dictionary()` callback which prompts the user with `askopenfilename`.
- Upon successful loading, assign the new definitions, update the window title to indicate a custom dictionary is in use, and re-parse the active `.cdf` file if one is loaded.

---

### Phase 4: Packaging

#### [NEW] [build_release.py](file:///c:/Users/markn/OneDrive%20-%20IXL%20Signalling/0-01%20AI%20Programming/AI%20Coding/AMS2_CDF_Editor/AMS2-CDF-File-Editor/build_release.py)
- Create a Python script to automate PyInstaller builds using `subprocess`.
- Build the standalone executable (`--onefile`) and portable version (`--onedir`).
- Include `--add-data "../cdf-hex-map.xml;."` (or appropriate absolute path relative to the script) to embed the dictionary.

## Verification Plan

### Automated Tests
- Run `pytest tests/test_dict_loading.py tests/test_cdf_editor_gui.py` to ensure loading and GUI refresh behavior is robust.

### Manual Verification
- Compile using `build_release.py`.
- Open the `.exe`. Verify it parses a CDF correctly out-of-the-box (using embedded definitions).
- Use `File -> Load Custom Dictionary`, select an altered XML, and verify the GUI instantly updates the parameters tree to reflect the new definitions.
