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

    def test_internal_dictionary_fallback(self):
        """Test that default_dictionary.py is used when no path is provided"""
        try:
            with patch('xml.etree.ElementTree.fromstring') as mock_fromstring:
                from default_dictionary import XML_CONTENT
                # mock fromstring to return a dummy Element to prevent crashes down the line
                import xml.etree.ElementTree as ET
                mock_fromstring.return_value = ET.Element('root')
                load_dictionary()
                mock_fromstring.assert_called_once_with(XML_CONTENT)
        except ImportError:
            self.fail("default_dictionary.py should be importable for internal fallback")

if __name__ == '__main__':
    unittest.main()
