"""
build_release.py
Automates the PyInstaller build process for AMS2 CDF Editor.
Generates both a portable standalone executable (--onefile) and a portable directory version (--onedir).
"""

import os
import subprocess
import shutil
import glob

def generate_internal_dict():
    """Converts the XML into a python string so PyInstaller can compile it natively."""
    xml_path = os.path.join(os.path.dirname(__file__), '..', 'cdf-hex-map.xml')
    out_path = os.path.join(os.path.dirname(__file__), 'default_dictionary.py')
    
    with open(xml_path, 'r', encoding='utf-8') as f:
        xml_content = f.read()
        
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('"""Auto-generated during build. Do not edit."""\n')
        f.write('XML_CONTENT = r"""')
        f.write(xml_content)
        f.write('"""\n')
    print("Generated default_dictionary.py for bulletproof embedding.")

def run_build():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, 'dist')
    build_dir = os.path.join(base_dir, "build")
    
    # Clean previous builds
    for d in [dist_dir, build_dir]:
        if os.path.exists(d):
            print(f"Cleaning {d}...")
            try:
                shutil.rmtree(d)
            except Exception as e:
                print(f"shutil.rmtree failed: {e}. Attempting cmd /c rmdir...")
                subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", d], check=False)
            
    print("Starting PyInstaller builds...")
    
    generate_internal_dict()

    # Build 1: Portable Standalone (--onefile)
    print("\n--- Building Standalone Executable (--onefile) ---")
    subprocess.run([
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "AMS2_CDF_Editor_Standalone",
        "cdf_editor_gui.py"
    ], check=True, cwd=base_dir)

    # Build 2: Portable Directory (--onedir)
    print("\n--- Building Portable Directory (--onedir) ---")
    subprocess.run([
        "pyinstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--name", "AMS2_CDF_Editor_Portable",
        "cdf_editor_gui.py"
    ], check=True, cwd=base_dir)

    # Copy the templates and translations to the portable directory
    portable_dir = os.path.join(dist_dir, "AMS2_CDF_Editor_Portable")
    xml_path = os.path.join(base_dir, "cdf-hex-map.xml")
    
    if os.path.exists(portable_dir):
        if os.path.exists(xml_path):
            shutil.copy2(xml_path, portable_dir)
        for txt_file in glob.glob(os.path.join(base_dir, "Translation*.txt")):
            shutil.copy2(txt_file, portable_dir)
        print("Successfully copied cdf-hex-map.xml and Translation files to the portable directory.")

    print("\nBuild process complete. Check the 'dist' directory.")

if __name__ == "__main__":
    run_build()
