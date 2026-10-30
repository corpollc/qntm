import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('version', Path(__file__).resolve().parents[1] / 'set_release_version.py')
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class ReleaseVersionTests(unittest.TestCase):
    def test_equivalent_package_versions(self):
        for npm, python in [('0.6.3', '0.6.3'), ('0.9.0-beta.1', '0.9.0b1'), ('1.0.0-alpha.2', '1.0.0a2'), ('1.0.0-rc.3', '1.0.0rc3')]:
            self.assertEqual(version.python_version(npm), python)

    def test_rejects_ambiguous_release_versions(self):
        for value in ['0.9.0beta1', 'v0.9.0-beta.1', '0.9.0-preview', '0.9.0+local']:
            with self.assertRaises(ValueError):
                version.python_version(value)
