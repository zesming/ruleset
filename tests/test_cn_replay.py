from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build


class CrossPlatformReplayTests(unittest.TestCase):
    def prepare(self, root: Path):
        published = {"platform": "darwin-arm64", "binary_sha256": "a" * 64}
        actual = {"platform": "linux-amd64", "binary_sha256": "b" * 64}
        sources = {}
        for key, spec in build.cn_direct.SOURCE_SPECS.items():
            data = (key + "\n").encode()
            path = root / spec["archive_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            sources[key] = {"sha256": build.sha256(data)}
        outputs = {}
        for relative in sorted(build.cn_direct.ALLOWED_OUTPUTS):
            data = (relative + "\n").encode()
            outputs[relative] = data
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        provenance = root / "upstream/provenance.json"
        provenance.write_bytes(build.pretty_json_bytes({"cn_direct": {"converter_execution": published}}))
        (root / build.REPORT_DIR / "evidence").mkdir(parents=True)
        candidate = SimpleNamespace(outputs=outputs, provenance={"converter_execution": actual})
        manifest = {"cn_direct": {"sources": sources, "fetch_metadata": {}}}
        return candidate, manifest, published, copy.deepcopy(actual), provenance.read_bytes()

    def test_other_platform_requires_explicit_replay_option(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, manifest, _, actual, original = self.prepare(root)
            with mock.patch.object(build, "_build_cn_candidate", return_value=candidate):
                with self.assertRaisesRegex(build.BuildError, "published converter platform"):
                    build._replay_cn_candidate(root, {"cn_direct": {}}, None, manifest)
            self.assertEqual(candidate.provenance["converter_execution"], actual)
            self.assertEqual((root / "upstream/provenance.json").read_bytes(), original)

    def test_each_different_output_rejects_before_execution_record_is_normalized(self):
        for relative in sorted(build.cn_direct.ALLOWED_OUTPUTS):
            with self.subTest(output=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate, manifest, _, actual, original = self.prepare(root)
                candidate.outputs[relative] += b"different converter output\n"
                with mock.patch.object(build, "_build_cn_candidate", return_value=candidate):
                    with self.assertRaisesRegex(build.BuildError, "Cross-platform CN-direct replay differs"):
                        build._replay_cn_candidate(root, {"cn_direct": {}}, None, manifest, True)
                self.assertEqual(candidate.provenance["converter_execution"], actual)
                self.assertEqual((root / "upstream/provenance.json").read_bytes(), original)
                self.assertFalse((root / build.REPORT_DIR / "evidence/cn-direct-cross-platform.json").exists())

    def test_equal_bytes_preserve_published_record_and_save_actual_execution_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, manifest, published, actual, original = self.prepare(root)
            with mock.patch.object(build, "_build_cn_candidate", return_value=candidate):
                result = build._replay_cn_candidate(root, {"cn_direct": {}}, None, manifest, True)
            self.assertEqual(result.provenance["converter_execution"], published)
            self.assertEqual((root / "upstream/provenance.json").read_bytes(), original)
            proof = json.loads((root / build.REPORT_DIR / "evidence/cn-direct-cross-platform.json").read_bytes())
            self.assertEqual(proof["published_execution"], published)
            self.assertEqual(proof["replay_execution"], actual)
            self.assertEqual(proof["output_sha256"], {p: build.sha256(data) for p, data in candidate.outputs.items()})


if __name__ == "__main__":
    unittest.main()
