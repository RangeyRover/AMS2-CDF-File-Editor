import unittest
from unittest import mock
import tkinter as tk
from tkinter import ttk
import os

try:
    from cdf_editor_gui import CdfEditorApp
except ImportError:
    # Fails intentionally for TDD
    CdfEditorApp = None

class TestCdfEditorGUI(unittest.TestCase):
    
    def setUp(self):
        if CdfEditorApp is None:
            self.fail("CdfEditorApp not implemented yet")
        
        # Initialize app but do not start mainloop
        self.app = CdfEditorApp()

    def tearDown(self):
        if hasattr(self, 'app') and self.app:
            self.app.destroy()

    def test_ui_components_exist(self):
        """Test that core UI elements are initialized"""
        # Ensure we have a Treeview
        self.assertIsInstance(self.app.tree, ttk.Treeview, "App must have a ttk.Treeview widget named 'tree'")
        
        # Ensure we have a Notes panel
        self.assertIsInstance(self.app.notes_text, tk.Text, "App must have a tk.Text widget named 'notes_text'")
        
        # Ensure we have a Search entry
        self.assertIsInstance(self.app.search_var, tk.StringVar, "App must have a tk.StringVar named 'search_var'")
        self.assertIsInstance(self.app.search_entry, ttk.Entry, "App must have a ttk.Entry named 'search_entry'")

    def test_treeview_hierarchy_built(self):
        """Test that the treeview contains sections, groups, and blocks after loading"""
        self.app.load_dictionary() # Load the bundled one
        
        # To populate the tree, we need a working blob that matches at least one definition
        # Let's find the signature for 'Mass' and create a dummy blob
        cg_def = next((d for d in self.app.cdf_defs if "Mass" in d.name), self.app.cdf_defs[0])
        self.app.working_blob = cg_def.marker + b'\x00' * 16 # marker + dummy payload
        self.app.refresh_parse()

        # There should be children in the tree
        root_children = self.app.tree.get_children()
        self.assertTrue(len(root_children) > 0, "Treeview must be populated with sections")
        
        # Pick the first section and ensure it has groups
        first_section = root_children[0]
        group_children = self.app.tree.get_children(first_section)
        self.assertTrue(len(group_children) > 0, "Section must have group children")
        
        # Pick the first group and ensure it has blocks
        first_group = group_children[0]
        block_children = self.app.tree.get_children(first_group)
        self.assertTrue(len(block_children) > 0, "Group must have block children")

    @mock.patch('tkinter.filedialog.askopenfilename')
    def test_load_custom_dictionary(self, mock_askopenfilename):
        """Test that loading a custom dictionary overrides the current definitions"""
        # Mock the file dialog to return the standard xml path (just for testing logic)
        mock_askopenfilename.return_value = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "cdf-hex-map.xml"))
        
        self.app.cdf_defs = [] # clear it
        self.app.load_custom_dictionary()
        self.assertTrue(len(self.app.cdf_defs) > 0, "Custom dictionary should be loaded")

if __name__ == '__main__':
    unittest.main()
