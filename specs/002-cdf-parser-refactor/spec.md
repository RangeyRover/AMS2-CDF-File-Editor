## 1. Feature Description
Refactor the monolithic `cdf_editorV0.2.py` into a modular `cdf_parser.py` that utilizes the newly generated `cdf-hex-map.xml` as its primary data definition source. This refactor will replace the hardcoded Python data structures with an XML-driven architecture, enabling a structured, hierarchical TreeView UI for parameter navigation (with live filtering) and integrating translation notes directly into the application.

## Clarifications
### Session 2026-04-19
- Q: Should we implement a search or filter mechanism to help users quickly locate specific parameters? → A: Yes, implement a live filter bar above the TreeView.
- Q: Should the editor remember a custom XML choice on restart? → A: No, keep it session-only. A fresh launch always reverts to the bundled, safe XML.

## 2. Business Value / Goals
- **Maintainability**: Moving parameter definitions from hardcoded Python dictionaries to an external XML schema drastically reduces the codebase size and complexity, making future updates trivial.
- **Usability**: The hierarchical XML structure allows the UI to present parameters in logical domain groups (e.g., "Suspension", "Aerodynamics") instead of a massive flat list.
- **Contextual Awareness**: Displaying the `<notes>` tags embedded in the XML directly within the UI eliminates the need for users to reference external translation text files.

## 3. User Scenarios
- **Scenario 1: Modding a Chassis File**
  - **Given** the user launches the CDF Editor and loads a `chassis.cdfbin` file,
  - **When** the file is parsed against `cdf-hex-map.xml`,
  - **Then** the UI populates a structured TreeView matching the documentation sections and groups, allowing the user to easily find "FRONT LEFT CORNER" -> "Brakes".
- **Scenario 2: Reading Variable Notes**
  - **Given** the user selects a specific variable like `CGHeight` in the TreeView,
  - **When** the variable is highlighted,
  - **Then** the right-hand panel displays the exact AMS2 translation notes, giving the user immediate context without leaving the app.

## 4. Functional Requirements
- **FR1: XML Parsing Engine**: The application must parse `cdf-hex-map.xml` on startup to dynamically construct the `CdfFieldDef` mapping.
- **FR2: UI TreeView Integration**: The Tkinter UI must be refactored from a flat `ttk.Treeview` to a multi-level hierarchical tree (`Section` -> `Group` -> `Block`).
- **FR3: Live Search/Filter**: A text input field must be provided above the TreeView. As the user types, the TreeView must actively filter and automatically expand nodes to display matching parameters.
- **FR4: Info/Notes Panel**: The UI must include a dedicated text widget or panel that displays the `<notes>` content for the currently selected parameter.
- **FR5: Payload Preservation**: In-place hex edits must continue to correctly encode and overwrite payloads without altering the file's byte length.

## 5. Success Criteria
- The hardcoded `CDF_DEFS` list is completely removed from the Python source code.
- The editor successfully loads and edits a CDF file using the XML schema with 100% data integrity.
- The UI reflects the three-level hierarchy defined in the XML.
- The application natively displays parameter translation notes in the UI.

## 6. Assumptions & Constraints
- The `cdf-hex-map.xml` file will be distributed alongside the executable.
- The XML structure (`<parameters>` -> `<section>` -> `<group>` -> `<block>`) is strictly enforced and valid.

## 7. Open Questions / Clarifications
- **[RESOLVED] Executable Distribution**: The application will bundle the `cdf-hex-map.xml` file into a `--onefile` executable so it remains a single standalone tool. However, the UI will include a "Load Custom Dictionary" option (e.g., under a 'File' or 'Advanced' menu) that allows advanced users to browse for and load their own `.xml` dictionary files, immediately reloading the parser and UI tree view to aid in community testing and discovery. This custom choice is strictly **session-only** and resets to the bundled XML upon application restart to prevent corrupted states.
