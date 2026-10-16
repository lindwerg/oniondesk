"""Frozen Linux must not inject its loader path into a system browser."""
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'client'))
import app


class PackagedBrowserTest(unittest.TestCase):
    def test_bundle_path_is_removed_and_restored_even_if_browser_fails(self):
        env = {'LD_LIBRARY_PATH':'/bundle/internal'}
        def browser(url):
            self.assertNotIn('LD_LIBRARY_PATH',os.environ)
            raise RuntimeError('controlled browser failure')
        with mock.patch.dict(os.environ,env,clear=True), mock.patch.object(sys,'platform','linux'), mock.patch.object(sys,'frozen',True,create=True), mock.patch.object(app.webbrowser,'open',side_effect=browser):
            with self.assertRaises(RuntimeError): app.open_system_browser('http://127.0.0.1/')
            self.assertEqual(os.environ['LD_LIBRARY_PATH'],'/bundle/internal')

    def test_original_path_is_used_for_browser_and_bundle_restored(self):
        env = {'LD_LIBRARY_PATH':'/bundle/internal','LD_LIBRARY_PATH_ORIG':'/system/original'}
        def browser(url):
            self.assertEqual(os.environ['LD_LIBRARY_PATH'],'/system/original')
            return True
        with mock.patch.dict(os.environ,env,clear=True), mock.patch.object(sys,'platform','linux'), mock.patch.object(sys,'frozen',True,create=True), mock.patch.object(app.webbrowser,'open',side_effect=browser):
            self.assertTrue(app.open_system_browser('http://127.0.0.1/'))
            self.assertEqual(os.environ['LD_LIBRARY_PATH'],'/bundle/internal')

if __name__=='__main__': unittest.main()
