import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_reference_release import build_release


class ReferenceReleaseTests(unittest.TestCase):
    def test_independent_source_directories_produce_identical_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            for name in ("source-a", "source-b"):
                source=base/name; source.mkdir()
                (source/"a.py").write_bytes(b"print('hello')\n")
                (source/"VERSION").write_bytes(b"1.0.0\n")
            a=build_release(base/"source-a",base/"out-a",["VERSION","a.py"],"1.0.0","b"*40)
            b=build_release(base/"source-b",base/"out-b",["a.py","VERSION"],"1.0.0","b"*40)
            self.assertEqual(a,b)
            for filename in ("e2eesa-source.tar.gz","release-manifest.json","sbom.spdx.json"):
                self.assertEqual((base/"out-a"/filename).read_bytes(),(base/"out-b"/filename).read_bytes())
            packed=(base/"out-a/e2eesa-source.tar.gz").read_bytes()
            self.assertEqual(a["artifact_digest"],"sha256:"+hashlib.sha256(packed).hexdigest())
            sbom=json.loads((base/"out-a/sbom.spdx.json").read_text())
            self.assertEqual(sbom["packages"][0]["checksums"][0]["checksumValue"],a["artifact_digest"][7:])
            with tarfile.open(base/"out-a/e2eesa-source.tar.gz") as archive:
                self.assertEqual(archive.getnames(),["VERSION","a.py"])
                for member in archive:
                    self.assertEqual((member.mtime,member.uid,member.gid),(0,0,0))

    def test_mutation_changes_real_archive_digest(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);source=base/"source";source.mkdir();(source/"a.py").write_bytes(b"original")
            a=build_release(source,base/"out-a",["a.py"],"1.0.0","b"*40)
            (source/"a.py").write_bytes(b"changed")
            b=build_release(source,base/"out-b",["a.py"],"1.0.0","b"*40)
            self.assertNotEqual(a["artifact_digest"],b["artifact_digest"])

    def test_escaping_symlink_duplicate_and_self_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);source=base/"source";source.mkdir();(source/"a.py").write_bytes(b"safe")
            (base/"outside").write_bytes(b"outside")
            (source/"link").symlink_to(base/"outside")
            for paths in (["../outside"],["/outside"],["link"],["a.py","a.py"],[".git/config"],["a\\b"]):
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    build_release(source,base/"out",paths,"1.0.0","b"*40)
            with self.assertRaises(ValueError):build_release(source,source/"out",["a.py"],"1.0.0","b"*40)


if __name__ == "__main__": unittest.main()
