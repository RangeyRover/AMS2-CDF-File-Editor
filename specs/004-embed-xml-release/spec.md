# Feature Specification: Embed XML, Custom Loading, and Final Polish

## 1. Feature Description
The AMS2 CDF Editor needs to be packaged for distribution. The core XML dictionary (`cdf-hex-map.xml`) must be embedded directly within the compiled executable (`--onefile`) so that users do not need to manage multiple files. Additionally, the application must provide a deliberate GUI menu option (e.g., File -> Load Custom Dictionary) to allow advanced users to load a custom `cdf-hex-map.xml` from any location. The application will never automatically or dynamically load external XMLs; the user must explicitly choose to override the embedded dictionary. 

Furthermore, this release includes a final polish phase for `cdf-hex-map.xml` to resolve or classify any remaining "Unknown" parameters identified in the corpus analysis, and the git repository requires a strict `.gitignore` to prevent tracking of unnecessary artifacts. A Test-Driven Development (TDD) approach must be employed before refactoring the code.

## 2. User Scenarios & Testing

### Scenario 1: Standard Execution (Embedded XML)
*   **Context:** The user runs the single-file executable (`--onefile` build).
*   **Action:** The user launches the application.
*   **Outcome:** The application successfully starts, relying exclusively on the internal, embedded `cdf-hex-map.xml` to parse files.

### Scenario 2: Advanced User (Deliberate Custom XML Load)
*   **Context:** The user wants to test experimental definitions.
*   **Action:** The user selects "File -> Load Custom Dictionary" from the application menu, opening a file dialog, and selects a `.xml` file from an arbitrary location.
*   **Outcome:** The application loads the selected XML file, replaces the active dictionary definitions in memory, and triggers a refresh of the currently open CDF file if one is loaded.

### Scenario 3: XML Polishing Completeness
*   **Context:** The final release build is being prepared.
*   **Action:** The corpus analyzer is run against the 500-vehicle corpus.
*   **Outcome:** The XML map contains the final, polished definitions with resolved "Unknowns" mapped properly, or securely categorized, reducing the remaining unknowns to an absolute minimum.

## 3. Functional Requirements

*   **FR1 [XML Embedding]:** The build process (e.g. PyInstaller) must embed `cdf-hex-map.xml` as a data resource.
*   **FR2 [Default Loading]:** The `load_dictionary()` function must default to resolving the path to the internal `_MEIPASS` directory (when running as a frozen PyInstaller bundle) or the source tree, ignoring external files by default.
*   **FR3 [Deliberate Override]:** The GUI must provide a "Load Custom Dictionary..." file menu option that prompts the user with a file dialog to select an XML map.
*   **FR4 [Active Refresh]:** Loading a custom dictionary must reload the currently active `.cdf` file against the new definitions.
*   **FR5 [XML Final Polish]:** The XML dictionary must undergo a final review and manual polish pass to address the remaining 26 unknowns where possible before release.
*   **FR6 [Git Configuration]:** A strict `.gitignore` must be present, ignoring `.cdf` corpuses, python caches, and analysis reports, tracking only project files and the main XML.
*   **FR7 [TDD Enforcement]:** Test coverage must be provided for the dictionary loading and GUI override logic before the implementation is modified.

## 4. Success Criteria
*   The application can be compiled to a single `--onefile` executable.
*   Running the single executable works perfectly using internal XML.
*   Users can deliberately load a custom XML from any drive/folder via the GUI, and the application correctly parses files using the new definitions.
*   The XML map is fully polished for release.
*   Automated tests (using `pytest`) correctly mock and verify the embedded loading logic and GUI dictionary swapping.
