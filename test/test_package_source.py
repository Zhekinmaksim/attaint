import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

script = pathlib.Path(__file__).resolve().parents[1] / "scripts/package_source.py"
spec = importlib.util.spec_from_file_location("package_source", script)
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class SourceArchiveTests(unittest.TestCase):
    def test_allowlist_hashes_and_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            for name in ["cli/tool.py", "node_modules/tool.py", "cli/__pycache__/hidden.py",
                         "runs/attempt-01-registry-api/report.json", "web/app.bundle.js", ".env"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("sample\n")
            destination = root / "web/source.zip"
            packaging.package(root, destination)
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual(set(archive.namelist()), {"cli/tool.py", "SHA256SUMS.json"})
                manifest = json.loads(archive.read("SHA256SUMS.json"))
                self.assertEqual(manifest["credential_pattern_scan"], "passed")
                self.assertEqual(manifest["files"][0]["path"], "cli/tool.py")
            first = destination.read_bytes()
            packaging.package(root, destination)
            self.assertEqual(first, destination.read_bytes())

    def test_credential_detection_does_not_echo_matching_value(self):
        value = "gh" + "p_" + "a" * 36
        with self.assertRaises(ValueError) as raised:
            packaging.scan_credentials("file.py", value.encode())
        self.assertNotIn(value, str(raised.exception))

    def test_json_escaped_source_is_scanned_after_decoding(self):
        source = 'PRIVATE_KEY = "0x' + 'a' * 64 + '"'
        with self.assertRaises(ValueError):
            packaging.scan_credentials("artifact.json", json.dumps({"source": source}).encode())

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            (root / "cli").mkdir()
            (root / "README.md").write_text("source\n")
            (root / "cli/linked.py").symlink_to(root / "README.md")
            with self.assertRaises(ValueError):
                packaging.package(root, root / "web/source.zip")


if __name__ == "__main__":
    unittest.main()
