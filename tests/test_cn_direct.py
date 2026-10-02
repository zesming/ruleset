from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build  # noqa: E402

cn_direct = build.cn_direct


FIXTURES = ROOT / "tests/fixtures/cn-direct"
SOURCE_FIXTURE = {
    "china_max": "china-max-domain.txt",
    "acl_china_domain": "acl-china-domain.list",
    "sukka_direct_clash": "sukka-direct.txt",
    "sukka_domestic_clash": "sukka-domestic.txt",
    "sukka_direct_surge": "sukka-direct.conf",
    "sukka_domestic_surge": "sukka-domestic.conf",
}


def fixture_sources() -> dict[str, bytes]:
    return {key: (FIXTURES / name).read_bytes() for key, name in SOURCE_FIXTURE.items()}


class CnDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads((ROOT / "policy.json").read_text(encoding="utf-8"))["cn_direct"]

    @staticmethod
    def small_policy(raw_sources: dict[str, bytes]) -> dict:
        policy = copy.deepcopy(CnDirectTests.policy)
        for name in cn_direct.SOURCE_ORDER:
            policy["sources"][name]["snapshot_sha256"] = cn_direct.sha256(raw_sources[name])
        policy["acl_review"]["source_sha256"] = cn_direct.sha256(raw_sources["acl_china_domain"])
        policy["acl_review"]["bootstrap_candidate_id"] = ""
        policy["china_max_wide_scope_review"]["source_sha256"] = cn_direct.sha256(raw_sources["china_max"])
        china_rules = cn_direct._parse_china_max(
            raw_sources["china_max"], "china_max", policy["sources"]["china_max"]["max_bytes"]
        )
        policy["china_max_initial_wide_suffixes"] = cn_direct.china_max_initial_wide_suffixes(
            china_rules, cn_direct.load_public_suffix_list()
        )
        policy["limits"]["minimum_output_rules"] = 1
        policy["limits"]["maximum_output_rules"] = 1000
        policy["first_match_assertions"] = []
        return policy

    @staticmethod
    def fixture_baseline(raw_sources: dict[str, bytes], policy: dict) -> dict:
        parsed = cn_direct.parse_sources(raw_sources, policy)
        source_rules = {name: cn_direct._unique_source_rules(parsed[name]) for name in cn_direct.SOURCE_ORDER}
        base_domains = [
            rule for name in (
                "china_max", "sukka_direct_clash", "sukka_domestic_clash",
                "sukka_direct_surge", "sukka_domestic_surge",
            ) for rule in parsed[name] if rule.type in cn_direct.DOMAIN_TYPES
        ]
        domain_rules, _ = cn_direct.compress_domain_rules(base_domains)
        return {"source_rules": source_rules, "domain_rules": domain_rules}

    @staticmethod
    def source_metadata(raw_sources: dict[str, bytes]) -> dict:
        return {
            "schema": 1,
            "sources": {
                name: {"sha256": cn_direct.sha256(raw_sources[name])}
                for name in cn_direct.SOURCE_ORDER
            },
        }

    @staticmethod
    def converter_result(policy: dict, mrs_bytes: bytes, execution: dict) -> tuple[bytes, dict, dict]:
        registry = {
            "version": policy["converter"]["version"],
            "command": policy["converter"]["command"],
            "binaries": policy["converter"]["binaries"],
            "registry_sha256": "a" * 64,
        }
        return mrs_bytes, registry, execution

    def test_parses_six_sources_and_keeps_platform_specific_rules_separate(self) -> None:
        parsed = cn_direct.parse_sources(fixture_sources(), self.policy)

        self.assertEqual(tuple(parsed), cn_direct.SOURCE_ORDER)
        self.assertTrue(any(rule.type == "DOMAIN-KEYWORD" for rule in parsed["acl_china_domain"]))
        self.assertTrue(any(rule.type == "IP-CIDR" for rule in parsed["acl_china_domain"]))
        self.assertFalse(any(rule.type == "USER-AGENT" for rule in parsed["sukka_direct_clash"]))
        diff = cn_direct._check_client_source_semantics(parsed)
        self.assertEqual(diff["sukka_direct"]["surge_only_types"], ["USER-AGENT"])
        self.assertEqual(diff["sukka_direct"]["surge_user_agents"], ["Direct Agent/*"])

    def test_rejects_unknown_rule_types_and_clash_user_agent(self) -> None:
        raw = fixture_sources()
        raw["sukka_direct_clash"] += b"USER-AGENT,not-supported\n"
        with self.assertRaisesRegex(cn_direct.CnDirectError, "must not contain USER-AGENT"):
            cn_direct.parse_sources(raw, self.policy)

        raw = fixture_sources()
        raw["sukka_domestic_surge"] += b"UNKNOWN,anything\n"
        with self.assertRaisesRegex(cn_direct.CnDirectError, "unknown Sukka source type"):
            cn_direct.parse_sources(raw, self.policy)

    def test_initial_snapshot_hash_mismatch_holds_each_registered_source(self) -> None:
        original = fixture_sources()
        policy = self.small_policy(original)
        additions = {
            "china_max": b".new-initial.example\n",
            "acl_china_domain": b"DOMAIN-SUFFIX,new-initial.example\n",
            "sukka_direct_clash": b"DOMAIN-SUFFIX,new-initial.example\n",
            "sukka_domestic_clash": b"DOMAIN-SUFFIX,new-initial.example\n",
            "sukka_direct_surge": b"USER-AGENT,New Initial Agent/*\n",
            "sukka_domestic_surge": b"USER-AGENT,New Initial Agent/*\n",
        }

        for source in cn_direct.SOURCE_ORDER:
            with self.subTest(source=source):
                changed = dict(original)
                changed[source] += additions[source]
                with mock.patch.object(cn_direct, "_convert_mrs") as convert:
                    with self.assertRaisesRegex(
                        cn_direct.CnDirectError,
                        f"initial {source} bytes do not match the reviewed source snapshot SHA",
                    ):
                        cn_direct.build_candidate(changed, policy, converter_path="unused")
                    convert.assert_not_called()

    def test_unreviewed_acl_candidate_holds_and_reviewed_candidate_is_excluded(self) -> None:
        raw = fixture_sources()
        raw["acl_china_domain"] += (
            b"DOMAIN-SUFFIX,held.example\n"
            b"DOMAIN-SUFFIX,unreviewed.example\n"
        )
        policy = self.small_policy(raw)
        held_decision = {
            "type": "DOMAIN-SUFFIX",
            "value": "held.example",
            "action": "candidate",
            "reason": "Fixture hold: needs domain review.",
            "evidence": "fixture source line",
            "review_date": "2026-10-03",
        }
        policy["acl_review"]["decisions"].append(held_decision)
        baseline = self.fixture_baseline(raw, policy)
        published_execution = {"platform": "test", "binary_sha256": "b" * 64}
        converter = self.converter_result(policy, b"fixture-mrs", published_execution)

        with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            candidate = cn_direct.build_candidate(raw, policy, baseline=baseline, converter_path="unused")
        self.assertEqual(candidate.unreviewed_candidates, [
            {"type": "DOMAIN-SUFFIX", "value": "unreviewed.example"},
        ])
        self.assertEqual(candidate.manifest["acl_review"]["held"], [
            {"type": "DOMAIN-SUFFIX", "value": "held.example"},
        ])
        output_scopes = {(item["type"], item["value"]) for item in candidate.domain_rules}
        self.assertNotIn(("DOMAIN-SUFFIX", "held.example"), output_scopes)
        self.assertNotIn(("DOMAIN-SUFFIX", "unreviewed.example"), output_scopes)

        build_baseline = build.Baseline("a" * 64, {}, {}, baseline)
        with mock.patch.dict("os.environ", {"MIHOMO_CONVERTER": "unused"}), \
                mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            with self.assertRaisesRegex(build.BuildError, "CN-direct candidate requires review"):
                build._build_cn_candidate(
                    {"cn_direct": policy},
                    build_baseline,
                    raw,
                    self.source_metadata(raw),
                )

    def test_domain_compression_preserves_coverage_and_origin_counts(self) -> None:
        source_rules = [
            cn_direct.Rule("DOMAIN-SUFFIX", "example.com", "china_max", 1, ".example.com"),
            cn_direct.Rule("DOMAIN-SUFFIX", "child.example.com", "acl_china_domain", 1, "DOMAIN-SUFFIX,child.example.com"),
            cn_direct.Rule("DOMAIN", "host.example.com", "sukka_direct_clash", 1, "DOMAIN,host.example.com"),
            cn_direct.Rule("DOMAIN", "other.test", "sukka_direct_clash", 2, "DOMAIN,other.test"),
        ]
        output, origins = cn_direct.compress_domain_rules(source_rules)

        self.assertEqual(output, [
            {"type": "DOMAIN", "value": "other.test"},
            {"type": "DOMAIN-SUFFIX", "value": "example.com"},
        ])
        example_origin = next(item for item in origins if item["value"] == "example.com")
        self.assertEqual(example_origin["covered_input_rule_count"], 3)
        self.assertEqual(example_origin["source_rule_counts"], {
            "acl_china_domain": 1,
            "china_max": 1,
            "sukka_direct_clash": 1,
        })

    def test_pinned_psl_applies_exact_wildcard_exception_and_idna_rules(self) -> None:
        psl = cn_direct.load_public_suffix_list()

        self.assertEqual(psl.sha256, cn_direct.PSL_SHA256)
        self.assertEqual(psl.suffix_for("a.ck"), "a.ck")
        self.assertEqual(psl.suffix_for("www.ck"), "ck")
        self.assertEqual(psl.suffix_for("x.city.kawasaki.jp"), "kawasaki.jp")
        self.assertEqual(psl.suffix_for("foo.in.th"), "in.th")
        self.assertEqual(psl.suffix_for("公司.cn"), "xn--55qx5d.cn")
        with self.assertRaisesRegex(cn_direct.CnDirectError, "SHA-256"):
            cn_direct.load_public_suffix_list(b"com\n")

    def test_wide_scope_guard_uses_accepted_output_and_detects_parent_expansion(self) -> None:
        psl = cn_direct.load_public_suffix_list()

        added_parent = [{"type": "DOMAIN-SUFFIX", "value": "example.test"}]
        old_child = [{"type": "DOMAIN-SUFFIX", "value": "a.example.test"}]
        self.assertEqual(
            cn_direct._wide_scope_candidates(added_parent, old_child, psl),
            added_parent,
        )
        self.assertEqual(
            cn_direct._wide_scope_candidates(
                [{"type": "DOMAIN-SUFFIX", "value": "example.com"}],
                [{"type": "DOMAIN", "value": "example.com"}],
                psl,
            ),
            [{"type": "DOMAIN-SUFFIX", "value": "example.com"}],
        )
        self.assertEqual(
            cn_direct._wide_scope_candidates(
                [{"type": "DOMAIN-SUFFIX", "value": "foo.com"}],
                [{"type": "DOMAIN-SUFFIX", "value": "com"}],
                psl,
            ),
            [],
        )
        self.assertEqual(
            cn_direct._wide_scope_candidates(
                [{"type": "DOMAIN-SUFFIX", "value": "ck"}],
                [{"type": "DOMAIN-SUFFIX", "value": "a.ck"}],
                psl,
            ),
            [{"type": "DOMAIN-SUFFIX", "value": "ck"}],
        )

    def test_build_candidate_emits_fixed_bundle_and_provenance(self) -> None:
        raw = fixture_sources()
        parsed = cn_direct.parse_sources(raw, self.policy)
        baseline_sources = {name: cn_direct._unique_source_rules(parsed[name]) for name in cn_direct.SOURCE_ORDER}
        base_domains = [
            rule for name in (
                "china_max", "sukka_direct_clash", "sukka_domestic_clash",
                "sukka_direct_surge", "sukka_domestic_surge",
            ) for rule in parsed[name] if rule.type in cn_direct.DOMAIN_TYPES
        ]
        baseline_domains, _ = cn_direct.compress_domain_rules(base_domains)
        baseline = {"source_rules": baseline_sources, "domain_rules": baseline_domains}
        policy = copy.deepcopy(self.policy)
        policy["limits"]["minimum_output_rules"] = 1
        policy["limits"]["maximum_output_rules"] = 1000
        policy["first_match_assertions"] = []

        converter_registry = {
            "version": policy["converter"]["version"],
            "command": policy["converter"]["command"],
            "binaries": policy["converter"]["binaries"],
            "registry_sha256": "a" * 64,
        }
        with mock.patch.object(
            cn_direct,
            "_convert_mrs",
            return_value=(b"fixture-mrs", converter_registry, {"platform": "test", "binary_sha256": "b" * 64}),
        ):
            candidate = cn_direct.build_candidate(raw, policy, baseline=baseline, converter_path="unused")

        self.assertEqual(set(candidate.outputs), cn_direct.ALLOWED_OUTPUTS)
        self.assertEqual(candidate.outputs[cn_direct.OUTPUT_PATHS["mihomo_domain_mrs"]], b"fixture-mrs")
        self.assertEqual(candidate.provenance["converter_execution"]["platform"], "test")
        self.assertEqual(candidate.manifest["first_match_evidence_validation"], "references_only")
        self.assertEqual(candidate.manifest["wide_scope_baseline"]["public_suffix_list"]["sha256"], cn_direct.PSL_SHA256)
        self.assertEqual(candidate.manifest["acl_review"]["excluded_type_counts"]["DOMAIN-KEYWORD"], 1)
        self.assertEqual(candidate.manifest["quantity_errors"], [])
        self.assertEqual(candidate.unreviewed_candidates, [])


if __name__ == "__main__":
    unittest.main()
