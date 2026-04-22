# AMS2 CDF File Editor (v0.3)

A powerful, standalone Windows application for parsing, viewing, and editing Automobilista 2 (AMS2) `.cdf` physics files. 

This editor replaces hex-editing workflows with a clean, tree-based GUI that translates raw binary data into human-readable parameters using a dynamically updated, community-driven XML dictionary.

![Screenshot Placeholder](https://via.placeholder.com/800x450.png?text=AMS2+CDF+Editor)

## Key Features

- **100% Parameter Coverage**: The editor ships with a built-in XML dictionary that maps every known physics parameter across 150+ engine block variants in the game. No more "Unknown" signatures.
- **Real-World Value Constraints**: The built-in dictionary has been statistically enriched against a corpus of 500 game files. When you click a parameter, the "Translation Notes" box instantly shows you the exact `[min..max]` boundary and `(average)` value enforced by the game engine.
- **Custom Overrides**: Modders can override the built-in dictionary via the `File -> Load Custom cdf-hex-map.xml` menu, allowing for safe experimentation without breaking the base application.
- **Bulletproof Portability**: The application is compiled natively with PyInstaller. The core physics dictionary is baked directly into the executable's bytecode, meaning it launches instantly and perfectly on any Windows machine with zero extraction errors or file-system dependencies.

## Installation & Usage

There are two ways to run the editor. Neither requires Python to be installed.

### Option 1: Standalone Executable (Recommended)
1. Download `AMS2_CDF_Editor_Standalone.exe` from the latest GitHub Release.
2. Double click the `.exe` to run. (The dictionary is fully embedded).

### Option 2: Portable Directory
1. Download `AMS2_CDF_Editor_Portable.zip` from the latest GitHub Release.
2. Extract the folder to your desktop.
3. Run `AMS2_CDF_Editor_Portable.exe` from inside the folder. (This is useful if you want faster startup times, as it skips PyInstaller's temporary unpacking step).

## For Modders: Customizing the Dictionary
The editor relies on an XML map (`cdf-hex-map.xml`) to know how to decode the binary data. If you discover a new signature or want to test a new parameter mapping:

1. Create a modified `cdf-hex-map.xml` file.
2. In the editor, click `File -> Load Custom cdf-hex-map.xml...`
3. Select your modified file. The application title bar will instantly update to show you are in "Custom Dictionary" mode.

## Development & Building from Source

If you wish to contribute to the codebase:

1. Clone the repository.
2. Install dependencies (Tkinter is included in standard Python distributions).
3. Run `build_release.py` to automatically serialize the XML dictionary and compile the `.exe` and `.zip` artifacts into the `dist/` folder.

## License
Provided for the AMS2 Modding Community. 
