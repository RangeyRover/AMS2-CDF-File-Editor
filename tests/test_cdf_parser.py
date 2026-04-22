import unittest
import os
import sys
from unittest.mock import patch

try:
    from cdf_parser import load_dictionary, CdfFieldDef
except ImportError:
    # Fails intentionally for TDD
    pass

class TestCdfParser(unittest.TestCase):
    
    def setUp(self):
        # Path to the actual XML file in the project (it's one level above the project folder)
        self.xml_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "cdf-hex-map.xml"))
        self.assertTrue(os.path.exists(self.xml_path), "Test requires cdf-hex-map.xml to exist")

    def test_load_dictionary_default_path(self):
        """Test loading dictionary without providing a path (uses _MEIPASS or local dir)"""
        # This will test the local fallback since we don't have _MEIPASS set
        defs = load_dictionary()
        self.assertTrue(len(defs) > 0, "Should load at least one definition")
        self.assertIsInstance(defs[0], CdfFieldDef)

    def test_load_dictionary_custom_path(self):
        """Test loading dictionary from a specific path"""
        defs = load_dictionary(self.xml_path)
        self.assertTrue(len(defs) > 0, "Should load definitions from custom path")

    def test_parsed_field_def_properties(self):
        """Test that group and notes are correctly parsed from the XML structure"""
        defs = load_dictionary(self.xml_path)
        
        # Find a known variable, e.g., CGHeight
        cg_height_def = next((d for d in defs if d.name == "CGHeight"), None)
        self.assertIsNotNone(cg_height_def, "CGHeight must exist in the XML")
        
        # Verify new fields
        self.assertTrue(hasattr(cg_height_def, 'group'))
        self.assertIsNotNone(cg_height_def.group)
        self.assertTrue(hasattr(cg_height_def, 'notes'))
        
        # Since CGHeight has notes, let's verify notes isn't just an empty string for everything
        # Check that at least some definition has notes populated
        notes_found = any(len(d.notes) > 0 for d in defs)
        self.assertTrue(notes_found, "At least one CdfFieldDef should have notes populated from XML")

    @patch('sys._MEIPASS', 'fake_meipass_dir', create=True)
    @patch('os.path.exists')
    def test_sys_meipass_fallback(self, mock_exists):
        """Test that PyInstaller _MEIPASS is checked first"""
        # Setup mock to simulate that cdf-hex-map.xml exists in fake_meipass_dir
        mock_exists.side_effect = lambda path: path == os.path.join('fake_meipass_dir', 'cdf-hex-map.xml')
        
        try:
            # We must mock the actual file parsing so it doesn't try to open fake path
            with patch('xml.etree.ElementTree.parse') as mock_parse:
                load_dictionary()
                mock_parse.assert_called_once_with(os.path.join('fake_meipass_dir', 'cdf-hex-map.xml'))
        except FileNotFoundError:
            self.fail("Should have used the fake _MEIPASS path")

if __name__ == '__main__':
    unittest.main()
