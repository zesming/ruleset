from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build  # noqa: E402


META_SHA_A = "a" * 40
META_SHA_B = "b" * 40
TOOL_HASH = "f" * 64


def fixture_sources() -> dict[str, bytes]:
    return {
        "global": (ROOT / "tests/fixtures/source-global.list").read_bytes(),
        "cn": (ROOT / "tests/fixtures/source-cn.list").read_bytes(),
        "network-test": (ROOT / "tests/fixtures/source-network-test.list").read_bytes(),
    }


def append_rules(source: bytes, *rules: str) -> bytes:
    text = source.decode("utf-8")
    if text and not text.endswith("\n"):
        text += "\n"
    return (text + "".join(rule + "\n" for rule in rules)).encode("utf-8")


def remove_rule(source: bytes, line: str) -> bytes:
    return "".join(item + "\n" for item in source.decode("utf-8").splitlines() if item != line).encode("utf-8")


def policy_value() -> dict:
    return copy.deepcopy(build.validate_policy(ROOT))


def candidate(
    sources: dict[str, bytes] | None = None,
    *,
    policy: dict | None = None,
    baseline: build.Baseline | None = None,
    meta_sha: str = META_SHA_A,
    cn_direct_candidate=None,
) -> build.Candidate:
    policy = copy.deepcopy(policy if policy is not None else policy_value())
    licenses, license_hash = build.license_snapshot(ROOT, policy)
    return build.build_candidate(
        raw_sources=sources or fixture_sources(),
        meta_sha=meta_sha,
        policy=policy,
        license_record=licenses,
        license_hash=license_hash,
        baseline=baseline,
        current_tool_hash=TOOL_HASH,
        cn_direct_candidate=cn_direct_candidate,
    )


def cn_candidate_with_scopes(*scopes: tuple[str, str], source_hash: str = "c" * 64):
    accepted = [
        {
            "type": typ,
            "value": value,
            "source": "china_max",
            "line": index,
            "raw": f"{typ},{value}",
        }
        for index, (typ, value) in enumerate(sorted(set(scopes)), 1)
    ]
    return SimpleNamespace(
        accepted_domain_rules=accepted,
        source_hashes={"china_max": source_hash},
        outputs={},
        manifest={"converter": None, "semantic_review_errors": []},
        provenance={},
    )


def record_tuple_set(manifest: dict, section: str) -> dict[str, list[tuple[str, str]]]:
    if section == "source":
        raw = manifest["normalized_source"]
    else:
        raw = {category: manifest["outputs"][category]["rules"] for category in build.SOURCE_CATEGORIES}
    return build._tuples_by_category(raw, section)


def baseline_from(candidate_value: build.Candidate) -> build.Baseline:
    return build._baseline_from_manifest(candidate_value.manifest, "test baseline")


def source_runner(sources: dict[str, bytes], meta_sha: str):
    def fake_fetch(*, on_meta_sha=None, on_source=None):
        if on_meta_sha:
            on_meta_sha(meta_sha)
        result = {}
        for category in build.SOURCE_CATEGORIES:
            result[category] = sources[category]
            if on_source:
                on_source(category, result[category])
        return meta_sha, result

    return fake_fetch


def prepare_temp_root(root: Path) -> None:
    (root / "scripts").mkdir(parents=True)
    (root / "tests/fixtures").mkdir(parents=True)
    (root / "licenses").mkdir()
    shutil.copy2(ROOT / "policy.json", root / "policy.json")
    for relative in build.TOOL_CONTENT_FILES:
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    copied_policy_path = root / "policy.json"
    copied_policy = json.loads(copied_policy_path.read_text(encoding="utf-8"))
    copied_policy.pop("cn_direct", None)
    copied_policy_path.write_text(json.dumps(copied_policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name in build.LICENSE_FILES:
        shutil.copy2(ROOT / "licenses" / name, root / "licenses" / name)
    (root / ".gitignore").write_text("/.build-report/\n", encoding="utf-8")


def initialize_git(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)


def commit_workspace(root: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", message], cwd=root, check=True, capture_output=True)


class RuleParsingTests(unittest.TestCase):
    def test_domain_normalization_dedup_and_strict_types(self) -> None:
        result = build.parse_source(
            b"DOMAIN,Example.COM.\nDOMAIN,example.com\nDOMAIN-SUFFIX,foo.example.com\n",
            "global",
            META_SHA_A,
        )
        self.assertEqual([(row.type, row.value) for row in result], [
            ("DOMAIN", "example.com"),
            ("DOMAIN-SUFFIX", "foo.example.com"),
        ])

    def test_empty_html_bad_domains_unknown_types_and_unknown_regex_fail(self) -> None:
        invalid = [
            b"",
            b"<!doctype html><html>not a rules file</html>\n",
            b"DOMAIN,192.0.2.1\n",
            b"DOMAIN,bad..example\n",
            b"DOMAIN,good.example,PROXY\n",
            b"DOMAIN-KEYWORD,openai\n",
            b"DOMAIN-REGEX,^other\\.example$\n",
        ]
        for source in invalid:
            with self.subTest(source=source):
                with self.assertRaises(build.BuildError):
                    build.parse_source(source, "global", META_SHA_A)

    def test_trailing_blank_and_whitespace_do_not_get_silently_ignored(self) -> None:
        for source in (b"DOMAIN,good.example\n\n", b" DOMAIN,good.example\n", b"DOMAIN,good.example \n"):
            with self.subTest(source=source):
                with self.assertRaises(build.BuildError):
                    build.parse_source(source, "cn", META_SHA_A)

    def test_domain_and_suffix_boundaries_are_exact(self) -> None:
        exact = build.Rule("DOMAIN", "example.com", "global")
        suffix = build.Rule("DOMAIN-SUFFIX", "example.com", "global")
        self.assertTrue(build.rule_matches_host(exact, "example.com"))
        self.assertFalse(build.rule_matches_host(exact, "api.example.com"))
        self.assertTrue(build.rule_matches_host(suffix, "example.com"))
        self.assertTrue(build.rule_matches_host(suffix, "api.example.com"))
        self.assertFalse(build.rule_matches_host(suffix, "notexample.com"))
        self.assertTrue(build.rules_overlap(exact, suffix))

    def test_registered_adapter_keeps_exact_fixed_scope_and_explicit_widening(self) -> None:
        rule = next(item for item in build.parse_source(fixture_sources()["global"], "global", META_SHA_A) if item.type == "DOMAIN-WILDCARD")
        self.assertEqual(rule.value, build.REGISTERED_WILDCARD)
        pattern = build._wildcard_regex(rule.value)
        widened = {
            "chatgpt-async-webps-prod--1.webpubsub.azure.com",
            "chatgpt-async-webps-prod-a-anything.webpubsub.azure.com",
        }
        for host in widened:
            self.assertTrue(pattern.fullmatch(host))
        self.assertFalse(pattern.fullmatch("chatgpt-async-webps-prod-a-1.webpubsub.azure.com.evil.test"))
        self.assertFalse(pattern.fullmatch("other-async-webps-prod-a-1.webpubsub.azure.com"))
        self.assertTrue(pattern.fullmatch("chatgpt-async-webps-prod-part.with.dot-42.webpubsub.azure.com"))


class PolicyAndBuildTests(unittest.TestCase):
    def test_eight_manual_entries_and_regex_adapter_are_emitted(self) -> None:
        result = candidate()
        global_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["global"]["rules"]}
        self.assertTrue({
            ("DOMAIN-SUFFIX", "ai.azure.com"),
            ("DOMAIN", "sydney.bing.com"),
            ("DOMAIN", "api.together.xyz"),
            ("DOMAIN", "api.github.com"),
            ("DOMAIN-SUFFIX", "ai.com"),
            ("DOMAIN-SUFFIX", "g.ai"),
            ("DOMAIN-SUFFIX", "cloudcode-pa.googleapis.com"),
            ("DOMAIN-SUFFIX", "anthropic.services"),
            ("DOMAIN-WILDCARD", build.REGISTERED_WILDCARD),
        }.issubset(global_rules))
        effects = result.manifest["counts"]["manual_adds"]
        self.assertEqual(len(effects), 8)
        self.assertEqual(result.manifest["counts"]["adapted_regex_rules"], 1)

    def test_cn_direct_full_coverage_moves_only_whole_domain_scopes(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(
            sources["global"],
            "DOMAIN,api.exact-covered.example.test",
            "DOMAIN,api.suffix-covered.example.test",
            "DOMAIN-SUFFIX,covered.example.test",
            "DOMAIN-SUFFIX,exact-only.example.test",
            "DOMAIN-SUFFIX,partial.example.test",
        )
        direct = cn_candidate_with_scopes(
            ("DOMAIN-SUFFIX", "covered.example.test"),
            ("DOMAIN", "api.exact-covered.example.test"),
            ("DOMAIN-SUFFIX", "suffix-covered.example.test"),
            ("DOMAIN", "exact-only.example.test"),
            ("DOMAIN", "host.partial.example.test"),
        )

        result = candidate(sources, cn_direct_candidate=direct)
        global_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["global"]["rules"]}
        cn_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["cn"]["rules"]}
        self.assertNotIn(("DOMAIN", "api.exact-covered.example.test"), global_rules)
        self.assertIn(("DOMAIN", "api.exact-covered.example.test"), cn_rules)
        self.assertIn(("DOMAIN", "api.suffix-covered.example.test"), cn_rules)
        self.assertNotIn(("DOMAIN-SUFFIX", "covered.example.test"), global_rules)
        self.assertIn(("DOMAIN-SUFFIX", "covered.example.test"), cn_rules)
        # A CN exact host cannot cover an AI suffix, even when the root host matches.
        self.assertIn(("DOMAIN-SUFFIX", "exact-only.example.test"), global_rules)
        self.assertIn(("DOMAIN-SUFFIX", "partial.example.test"), global_rules)

        audit = result.manifest["routing_ownership"]["rules"]
        by_value = {item["value"]: item for item in audit if item["category_before_auto"] == "global"}
        self.assertEqual(by_value["api.exact-covered.example.test"]["decision"], "auto_moved")
        self.assertEqual(by_value["api.suffix-covered.example.test"]["decision"], "auto_moved")
        self.assertEqual(by_value["covered.example.test"]["decision"], "auto_moved")
        self.assertEqual(by_value["exact-only.example.test"]["decision"], "partial_overlap_retained")
        self.assertEqual(by_value["partial.example.test"]["decision"], "partial_overlap_retained")
        self.assertIn("cover_evidence", by_value["covered.example.test"])
        self.assertEqual(by_value["covered.example.test"]["cover_evidence"][0]["source_sha256"], "c" * 64)
        self.assertEqual(by_value["covered.example.test"]["cover_evidence"][0]["archive_path"], "upstream/cn-direct/china-max-domain.txt")

        global_sources = {(item["type"], item["value"]) for item in result.manifest["normalized_source"]["global"]}
        self.assertIn(("DOMAIN-SUFFIX", "covered.example.test"), global_sources)
        self.assertTrue(any(
            origin["kind"] == "cn-direct-coverage"
            and origin["evidence"][0]["raw"] == "DOMAIN-SUFFIX,covered.example.test"
            for record in result.manifest["rule_origins"]
            if record["category"] == "cn" and record["value"] == "covered.example.test"
            for origin in record["origins"]
        ))

    def test_global_parent_overlap_stops_partial_auto_move_and_full_move_is_safe(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(
            sources["global"],
            "DOMAIN-SUFFIX,parent-guard.example.test",
            "DOMAIN,api.parent-guard.example.test",
        )
        with self.assertRaisesRegex(build.BuildError, "Automatic cn-direct classification would create a cross-category overlap"):
            candidate(
                sources,
                cn_direct_candidate=cn_candidate_with_scopes(("DOMAIN", "api.parent-guard.example.test")),
            )

        covered = candidate(
            sources,
            cn_direct_candidate=cn_candidate_with_scopes(("DOMAIN-SUFFIX", "parent-guard.example.test")),
        )
        covered_cn = {(item["type"], item["value"]) for item in covered.manifest["outputs"]["cn"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "parent-guard.example.test"), covered_cn)
        self.assertIn(("DOMAIN", "api.parent-guard.example.test"), covered_cn)

    def test_cn_direct_excludes_single_label_and_public_suffix_evidence(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(
            sources["global"],
            "DOMAIN-SUFFIX,service.co.uk",
            "DOMAIN-SUFFIX,service.foo.test",
        )
        result = candidate(
            sources,
            cn_direct_candidate=cn_candidate_with_scopes(
                ("DOMAIN-SUFFIX", "co.uk"),
                ("DOMAIN-SUFFIX", "test"),
            ),
        )
        global_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["global"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "service.co.uk"), global_rules)
        self.assertIn(("DOMAIN-SUFFIX", "service.foo.test"), global_rules)
        audit = result.manifest["routing_ownership"]["rules"]
        by_value = {item["value"]: item for item in audit if item["category_before_auto"] == "global"}
        self.assertEqual(by_value["service.co.uk"]["decision"], "broad_scope_only")
        self.assertEqual(by_value["service.co.uk"]["excluded_broad_scope"]["evidence"][0]["excluded_reason"], "public_suffix_scope")
        self.assertEqual(by_value["service.foo.test"]["decision"], "broad_scope_only")
        self.assertEqual(by_value["service.foo.test"]["excluded_broad_scope"]["evidence"][0]["excluded_reason"], "single_label_scope")

    def test_overlapping_explicit_global_add_or_move_protects_entire_source_rule(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(sources["global"], "DOMAIN-SUFFIX,vendor-override.example.test")
        sources["cn"] = append_rules(sources["cn"], "DOMAIN,host.move-override.example.test")
        policy = policy_value()
        policy["adds"].append({
            "category": "global",
            "type": "DOMAIN",
            "value": "api.vendor-override.example.test",
            "reason": "Fixture explicit global exception.",
            "reference": "https://example.invalid/global-exception",
            "review_date": "2026-10-09",
        })
        policy["moves"].append({
            "type": "DOMAIN",
            "value": "host.move-override.example.test",
            "to": "global",
            "reason": "Fixture explicit global move.",
        })
        result = candidate(
            sources,
            policy=policy,
            cn_direct_candidate=cn_candidate_with_scopes(
                ("DOMAIN-SUFFIX", "vendor-override.example.test"),
                ("DOMAIN-SUFFIX", "move-override.example.test"),
            ),
        )
        global_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["global"]["rules"]}
        cn_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["cn"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "vendor-override.example.test"), global_rules)
        self.assertIn(("DOMAIN", "host.move-override.example.test"), global_rules)
        self.assertNotIn(("DOMAIN", "host.move-override.example.test"), cn_rules)
        audit = result.manifest["routing_ownership"]["rules"]
        add_item = next(item for item in audit if item["value"] == "vendor-override.example.test")
        move_item = next(item for item in audit if item["value"] == "host.move-override.example.test")
        self.assertEqual(add_item["decision"], "explicit_global_protected")
        self.assertEqual(add_item["explicit_global_protection"], [{"kind": "add", "type": "DOMAIN", "value": "api.vendor-override.example.test"}])
        self.assertEqual(move_item["decision"], "explicit_global_protected")

    def test_ai_cn_and_network_test_keep_categories_when_direct_scopes_overlap(self) -> None:
        sources = fixture_sources()
        sources["cn"] = append_rules(sources["cn"], "DOMAIN-SUFFIX,cn-overlap.example.test")
        sources["network-test"] = append_rules(sources["network-test"], "DOMAIN-SUFFIX,test-overlap.example.test")
        result = candidate(
            sources,
            cn_direct_candidate=cn_candidate_with_scopes(("DOMAIN-SUFFIX", "example.test")),
        )
        cn_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["cn"]["rules"]}
        test_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["network-test"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "cn-overlap.example.test"), cn_rules)
        self.assertIn(("DOMAIN-SUFFIX", "test-overlap.example.test"), test_rules)
        audit = result.manifest["routing_ownership"]["rules"]
        self.assertEqual(next(item for item in audit if item["value"] == "cn-overlap.example.test")["decision"], "preserve_ai_cn")
        self.assertEqual(next(item for item in audit if item["value"] == "test-overlap.example.test")["decision"], "preserve_network_test")
        self.assertNotIn(("DOMAIN-WILDCARD", build.REGISTERED_WILDCARD), {
            (item["type"], item["value"]) for item in result.manifest["outputs"]["cn"]["rules"]
        })
        self.assertFalse(any(item["type"] == "DOMAIN-WILDCARD" for item in audit))

    def test_global_wildcard_overlap_is_audited_but_never_auto_moved(self) -> None:
        result = candidate(
            cn_direct_candidate=cn_candidate_with_scopes(("DOMAIN-SUFFIX", "webpubsub.azure.com")),
        )
        global_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["global"]["rules"]}
        self.assertIn(("DOMAIN-WILDCARD", build.REGISTERED_WILDCARD), global_rules)
        wildcard = next(item for item in result.manifest["routing_ownership"]["rules"] if item["type"] == "DOMAIN-WILDCARD")
        self.assertEqual(wildcard["decision"], "wildcard_manual_review")
        self.assertEqual(wildcard["direct_relation"], "possible_overlap")
        self.assertGreater(wildcard["possible_overlap"]["scope_count"], 0)
        self.assertIn("china_max", wildcard["possible_overlap"]["source_scope_counts"])

    def test_cn_direct_evidence_changes_move_back_and_restore_source_category(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(sources["global"], "DOMAIN-SUFFIX,appears-later.example.test")
        first = candidate(sources, cn_direct_candidate=cn_candidate_with_scopes())
        first_global = {(item["type"], item["value"]) for item in first.manifest["outputs"]["global"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "appears-later.example.test"), first_global)

        covered = cn_candidate_with_scopes(("DOMAIN-SUFFIX", "appears-later.example.test"), source_hash="d" * 64)
        second = candidate(sources, baseline=baseline_from(first), meta_sha=META_SHA_B, cn_direct_candidate=covered)
        second_cn = {(item["type"], item["value"]) for item in second.manifest["outputs"]["cn"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "appears-later.example.test"), second_cn)
        self.assertIn(("DOMAIN-SUFFIX", "appears-later.example.test"), {
            (item["type"], item["value"]) for item in second.manifest["normalized_source"]["global"]
        })
        self.assertIn({"type": "DOMAIN-SUFFIX", "value": "appears-later.example.test"}, second.manifest["diffs"]["output"]["global"]["removed"])

        third = candidate(sources, baseline=baseline_from(second), meta_sha="c" * 40, cn_direct_candidate=cn_candidate_with_scopes(source_hash="e" * 64))
        third_global = {(item["type"], item["value"]) for item in third.manifest["outputs"]["global"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "appears-later.example.test"), third_global)
        self.assertIn({"type": "DOMAIN-SUFFIX", "value": "appears-later.example.test"}, third.manifest["diffs"]["output"]["global"]["added"])

    def test_cn_direct_classification_does_not_bypass_source_migration_gate(self) -> None:
        first_sources = fixture_sources()
        first_sources["cn"] = append_rules(first_sources["cn"], "DOMAIN-SUFFIX,migration.example.test")
        first = candidate(first_sources, cn_direct_candidate=cn_candidate_with_scopes())
        migrated = {
            **first_sources,
            "global": append_rules(first_sources["global"], "DOMAIN,host.migration.example.test"),
        }
        with self.assertRaisesRegex(build.BuildError, "Unapproved cross-category source migration"):
            candidate(
                migrated,
                baseline=baseline_from(first),
                meta_sha=META_SHA_B,
                cn_direct_candidate=cn_candidate_with_scopes(("DOMAIN-SUFFIX", "migration.example.test")),
            )

    def test_anthropic_services_add_is_bounded_and_persistent(self) -> None:
        original_sources = fixture_sources()
        original = candidate(original_sources)
        with_upstream = dict(original_sources)
        with_upstream["global"] = append_rules(with_upstream["global"], "DOMAIN-SUFFIX,anthropic.services")
        added = candidate(with_upstream, baseline=baseline_from(original), meta_sha=META_SHA_B)
        removed = candidate(original_sources, baseline=baseline_from(added), meta_sha="c" * 40)
        self.assertEqual(original.outputs, added.outputs)
        self.assertEqual(original.outputs, removed.outputs)
        effect = next(item for item in added.manifest["counts"]["manual_adds"] if item["value"] == "anthropic.services")
        self.assertEqual(effect["result"], "redundant")
        records = [
            build.Rule(item["type"], item["value"], category)
            for category in build.SOURCE_CATEGORIES
            for item in original.manifest["outputs"][category]["rules"]
        ]
        for host in ("anthropic.services", "api.anthropic.services"):
            self.assertEqual({item.category for item in records if build.rule_matches_host(item, host)}, {"global"})
        for host in ("notanthropic.services", "anthropic.services.evil.test", "services"):
            self.assertFalse(any(build.rule_matches_host(item, host) for item in records))

    def test_add_already_covered_by_same_category_is_redundant(self) -> None:
        policy = policy_value()
        policy["adds"].append({
            "category": "global",
            "type": "DOMAIN-SUFFIX",
            "value": "openai.com",
            "reason": "Fixture for covered add handling.",
            "reference": "fixture",
            "review_date": "2026-09-26",
        })
        result = candidate(policy=policy)
        matching = [item for item in result.manifest["counts"]["manual_adds"] if item["value"] == "openai.com"]
        self.assertEqual(matching, [{"type": "DOMAIN-SUFFIX", "value": "openai.com", "category": "global", "result": "redundant"}])

    def test_add_conflicting_with_opposite_category_is_rejected(self) -> None:
        sources = fixture_sources()
        sources["cn"] = append_rules(sources["cn"], "DOMAIN,api.github.com")
        with self.assertRaisesRegex(build.BuildError, "Manual add.*conflicts with cn"):
            candidate(sources)

    def test_partial_remove_or_move_under_a_parent_suffix_fails(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(sources["global"], "DOMAIN-SUFFIX,company.example")
        policy = policy_value()
        policy["removes"] = [{"type": "DOMAIN", "value": "api.company.example", "reason": "Test narrow removal."}]
        with self.assertRaisesRegex(build.BuildError, "partly overlaps"):
            candidate(sources, policy=policy)

        policy["removes"] = []
        policy["moves"] = [{"type": "DOMAIN", "value": "api.company.example", "to": "cn", "reason": "Test narrow move."}]
        with self.assertRaisesRegex(build.BuildError, "partly overlaps"):
            candidate(sources, policy=policy)

    def test_partial_remove_under_registered_wildcard_fails(self) -> None:
        policy = policy_value()
        policy["removes"] = [{
            "type": "DOMAIN",
            "value": "chatgpt-async-webps-prod-a-1.webpubsub.azure.com",
            "reason": "Test partial wildcard removal.",
        }]
        with self.assertRaisesRegex(build.BuildError, "partly overlaps"):
            candidate(policy=policy)

    def test_policy_operations_may_not_overlap(self) -> None:
        policy = policy_value()
        policy["removes"] = [{"type": "DOMAIN-SUFFIX", "value": "example.com", "reason": "Remove parent."}]
        policy["moves"] = [{"type": "DOMAIN", "value": "api.example.com", "to": "cn", "reason": "Move child."}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(build.BuildError, "Overlapping policy intent"):
                build.validate_policy(root)

    def test_source_present_move_changes_category_then_becomes_inactive_after_deletion(self) -> None:
        first_sources = fixture_sources()
        first = candidate(first_sources)
        moved_sources = {
            "global": remove_rule(first_sources["global"], "DOMAIN,api.example-global.com"),
            "cn": append_rules(first_sources["cn"], "DOMAIN,api.example-global.com"),
            "network-test": first_sources["network-test"],
        }
        policy = policy_value()
        policy["moves"] = [{"type": "DOMAIN", "value": "api.example-global.com", "to": "cn", "reason": "Route with current domestic source classification."}]
        second = candidate(moved_sources, policy=policy, baseline=baseline_from(first), meta_sha=META_SHA_B)
        self.assertIn(("DOMAIN", "api.example-global.com"), {tuple((item["type"], item["value"])) for item in second.manifest["outputs"]["cn"]["rules"]})
        self.assertNotIn(("DOMAIN", "api.example-global.com"), {tuple((item["type"], item["value"])) for item in second.manifest["outputs"]["global"]["rules"]})
        self.assertEqual(second.manifest["diffs"]["source_migrations"][0]["approved_by"][0]["to"], "cn")

        deleted_sources = {
            "global": moved_sources["global"],
            "cn": remove_rule(moved_sources["cn"], "DOMAIN,api.example-global.com"),
            "network-test": moved_sources["network-test"],
        }
        third = candidate(deleted_sources, policy=policy, baseline=baseline_from(second), meta_sha="c" * 40)
        self.assertEqual(third.manifest["counts"]["moves"][0]["state"], "inactive")
        third_cn = {(item["type"], item["value"]) for item in third.manifest["outputs"]["cn"]["rules"]}
        self.assertNotIn(("DOMAIN", "api.example-global.com"), third_cn)
        self.assertIn(("DOMAIN", "api.github.com"), {(item["type"], item["value"]) for item in third.manifest["outputs"]["global"]["rules"]})

    def test_unapproved_and_reverse_source_migrations_are_blocked(self) -> None:
        first_sources = fixture_sources()
        first = candidate(first_sources)
        moved_sources = {
            "global": remove_rule(first_sources["global"], "DOMAIN,api.example-global.com"),
            "cn": append_rules(first_sources["cn"], "DOMAIN,api.example-global.com"),
            "network-test": first_sources["network-test"],
        }
        with self.assertRaisesRegex(build.BuildError, "Unapproved cross-category source migration"):
            candidate(moved_sources, baseline=baseline_from(first), meta_sha=META_SHA_B)

        policy = policy_value()
        policy["moves"] = [{"type": "DOMAIN", "value": "api.example-global.com", "to": "global", "reason": "Old destination is intentionally retained."}]
        with self.assertRaisesRegex(build.BuildError, "Unapproved cross-category source migration"):
            candidate(moved_sources, policy=policy, baseline=baseline_from(first), meta_sha=META_SHA_B)

    def test_suffix_move_preserves_original_exact_rule_types(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(sources["global"], "DOMAIN,one.example.org", "DOMAIN,two.example.org")
        policy = policy_value()
        policy["moves"] = [{"type": "DOMAIN-SUFFIX", "value": "example.org", "to": "cn", "reason": "Move current exact entries."}]
        result = candidate(sources, policy=policy)
        moved = {(item["type"], item["value"]) for item in result.manifest["outputs"]["cn"]["rules"]}
        self.assertIn(("DOMAIN", "one.example.org"), moved)
        self.assertIn(("DOMAIN", "two.example.org"), moved)
        self.assertNotIn(("DOMAIN-SUFFIX", "example.org"), moved)

    def test_unchanged_upstream_conflict_resolved_by_move_or_remove_stays_accepted(self) -> None:
        sources = fixture_sources()
        sources["global"] = append_rules(sources["global"], "DOMAIN,shared.example")
        sources["cn"] = append_rules(sources["cn"], "DOMAIN,shared.example")
        move_policy = policy_value()
        move_policy["moves"] = [{"type": "DOMAIN", "value": "shared.example", "to": "cn", "reason": "Resolve existing upstream conflict."}]
        first = candidate(sources, policy=move_policy)
        second = candidate(sources, policy=move_policy, baseline=baseline_from(first), meta_sha=META_SHA_B)
        self.assertEqual(second.manifest["diffs"]["source_migrations"], [])

        remove_policy = policy_value()
        remove_policy["removes"] = [{"type": "DOMAIN", "value": "shared.example", "reason": "Exclude both existing source entries."}]
        first_removed = candidate(sources, policy=remove_policy)
        second_removed = candidate(sources, policy=remove_policy, baseline=baseline_from(first_removed), meta_sha=META_SHA_B)
        self.assertEqual(second_removed.manifest["diffs"]["source_migrations"], [])

    def test_unchanged_registered_wildcard_conflict_stays_resolved(self) -> None:
        sources = fixture_sources()
        regex_line = "DOMAIN-REGEX," + build.REGISTERED_REGEX
        sources["cn"] = append_rules(sources["cn"], regex_line)
        for operation in ("moves", "removes"):
            with self.subTest(operation=operation):
                policy = policy_value()
                selector = {
                    "type": "DOMAIN-SUFFIX",
                    "value": "webpubsub.azure.com",
                    "reason": "Resolve the already accepted wildcard overlap.",
                }
                if operation == "moves":
                    selector["to"] = "cn"
                policy[operation] = [selector]
                first = candidate(sources, policy=policy)
                second = candidate(sources, policy=policy, baseline=baseline_from(first), meta_sha=META_SHA_B)
                self.assertEqual(second.manifest["diffs"]["source_migrations"], [])
                self.assertEqual(second.outputs, first.outputs)

        original = fixture_sources()
        baseline = candidate(original)
        migrated = {
            "global": remove_rule(original["global"], regex_line),
            "cn": append_rules(original["cn"], regex_line),
            "network-test": original["network-test"],
        }
        with self.assertRaisesRegex(build.BuildError, "Unapproved cross-category source migration"):
            candidate(migrated, baseline=baseline_from(baseline), meta_sha=META_SHA_B)

    def test_route_assertion_fixture_matches_policy(self) -> None:
        fixture = json.loads((ROOT / "tests/fixtures/routes.json").read_text(encoding="utf-8"))
        assertions = {category: sorted(item["host"] for item in policy_value()["route_assertions"] if item["category"] == category) for category in build.SOURCE_CATEGORIES}
        self.assertEqual(assertions, {category: sorted(hosts) for category, hosts in fixture.items()})

    def test_description_changes_and_policy_list_order_do_not_change_manifest(self) -> None:
        sources = fixture_sources()
        original = candidate(sources)
        changed_policy = policy_value()
        changed_policy["adds"] = list(reversed(changed_policy["adds"]))
        changed_policy["adds"][0]["reason"] = "Reworded maintenance note."
        changed_policy["adds"][0]["reference"] = "https://example.invalid/source"
        changed_policy["adds"][0]["review_date"] = "2026-09-27"
        changed = candidate(sources, policy=changed_policy)
        self.assertEqual(original.candidate_id, changed.candidate_id)
        self.assertEqual(original.release_id, changed.release_id)
        self.assertEqual(original.manifest, changed.manifest)

    def test_semantic_policy_operation_order_is_canonical(self) -> None:
        left = policy_value()
        left["moves"] = [
            {"type": "DOMAIN", "value": "one.example", "to": "cn", "reason": "first"},
            {"type": "DOMAIN", "value": "two.example", "to": "global", "reason": "second"},
        ]
        right = copy.deepcopy(left)
        right["moves"] = list(reversed(right["moves"]))
        self.assertEqual(build.canonical_bytes(build.semantic_policy(left)), build.canonical_bytes(build.semantic_policy(right)))

    def test_large_source_and_output_delta_is_accepted_and_reported(self) -> None:
        first = candidate()
        baseline = baseline_from(first)
        new_sources = fixture_sources()
        additions = [f"DOMAIN,new-{index}.example" for index in range(1_101)]
        new_sources["global"] = append_rules(new_sources["global"], *additions)
        result = candidate(new_sources, baseline=baseline, meta_sha=META_SHA_B)

        self.assertEqual(len(result.manifest["diffs"]["source"]["global"]["added"]), 1_101)
        self.assertEqual(len(result.manifest["diffs"]["output"]["global"]["added"]), 1_101)
        self.assertGreater(len(result.manifest["outputs"]["global"]["rules"]), 1_000)
        self.assertNotIn("quantity_errors", result.manifest)

    def test_upstream_byte_limit_and_nonempty_format_guards_remain(self) -> None:
        sources = fixture_sources()
        sources["global"] = b"x" * (build.MAX_SOURCE_BYTES + 1)
        with self.assertRaisesRegex(build.BuildError, "global source exceeds the size limit"):
            candidate(sources)

        empty_sources = fixture_sources()
        empty_sources["network-test"] = b""
        with self.assertRaisesRegex(build.BuildError, "network-test source is empty"):
            candidate(empty_sources)

    def test_candidate_changes_when_source_tool_semantics_or_baseline_changes(self) -> None:
        base = candidate()
        parsed_baseline = baseline_from(base)
        other_baseline = build.Baseline("1" * 64, parsed_baseline.source_rules, parsed_baseline.output_rules)
        with_new_baseline = candidate(baseline=other_baseline)
        self.assertNotEqual(base.candidate_id, with_new_baseline.candidate_id)
        self.assertEqual(base.release_id, with_new_baseline.release_id)
        with_changed_tool = build.build_candidate(
            raw_sources=fixture_sources(), meta_sha=META_SHA_A, policy=policy_value(),
            license_record=build.license_snapshot(ROOT, policy_value())[0],
            license_hash=build.license_snapshot(ROOT, policy_value())[1], baseline=None,
            current_tool_hash="e" * 64,
        )
        self.assertNotEqual(base.release_id, with_changed_tool.release_id)


class NetworkTestCategoryTests(unittest.TestCase):
    def test_combine_source_chunks_filters_unregistered_regex(self) -> None:
        chunks = [
            b"DOMAIN,foo.example\nDOMAIN-REGEX,^speed.*\\.ooklaserver\\.net$\n",
            b"DOMAIN-SUFFIX,bar.example\n",
        ]
        combined = build._combine_source_chunks(chunks, "network-test")
        lines = combined.decode("utf-8").splitlines()
        self.assertEqual(lines, ["DOMAIN,foo.example", "DOMAIN-SUFFIX,bar.example"])
        self.assertNotIn("DOMAIN-REGEX", combined.decode("utf-8"))

    def test_network_test_upstream_rules_are_emitted(self) -> None:
        result = candidate()
        nt_rules = {(item["type"], item["value"]) for item in result.manifest["outputs"]["network-test"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "whatismyip.com"), nt_rules)
        self.assertIn(("DOMAIN-SUFFIX", "speedtest.net"), nt_rules)
        self.assertIn(("DOMAIN-SUFFIX", "ipinfo.io"), nt_rules)
        self.assertNotIn(("DOMAIN", "whatismyip.akamai.com"), nt_rules)
        self.assertIn(("DOMAIN-SUFFIX", "fast.com"), nt_rules)
        direct_lines = result.manual_files[build.DIRECT_RULES_PATH].decode("utf-8").splitlines()
        self.assertIn("DOMAIN,whatismyip.akamai.com", direct_lines)

    def test_surge_domain_set_conversion_matches_classical_semantics(self) -> None:
        rules = [
            {"type": "DOMAIN", "value": "whatismyip.akamai.com"},
            {"type": "DOMAIN-SUFFIX", "value": "whatismyip.com"},
            {"type": "DOMAIN-SUFFIX", "value": "speedtest.net"},
        ]
        result = build._to_surge_domain_set(rules).decode("utf-8")
        lines = result.splitlines()
        # DOMAIN (exact) -> no leading dot; DOMAIN-SUFFIX -> leading dot
        self.assertIn("whatismyip.akamai.com", lines)
        self.assertIn(".whatismyip.com", lines)
        self.assertIn(".speedtest.net", lines)
        self.assertNotIn("DOMAIN-", result)
        self.assertTrue(result.endswith("\n"))

    def test_surge_domain_set_rejects_non_domain_rules(self) -> None:
        with self.assertRaises(build.BuildError):
            build._to_surge_domain_set([{"type": "DOMAIN-WILDCARD", "value": "*.example.com"}])

    def test_combine_preserves_registered_regex_for_global(self) -> None:
        # The registered Azure ChatGPT regex must survive _combine so parse_source
        # can emit the reviewed DOMAIN-WILDCARD. Unregistered regexes are still dropped.
        registered_line = f"DOMAIN-REGEX,{build.REGISTERED_REGEX}"
        unregistered = r"DOMAIN-REGEX,^speed\..*\.ooklaserver\.net$"
        chunk = f"DOMAIN-SUFFIX,example.com\n{registered_line}\n{unregistered}\n".encode("utf-8")
        combined = build._combine_source_chunks([chunk], "global").decode("utf-8")
        self.assertIn(registered_line, combined)
        self.assertNotIn(unregistered, combined)
        # parse_source should still emit the wildcard from the preserved regex
        rules = build.parse_source(combined.encode("utf-8"), "global", "test-sha")
        wildcards = [r for r in rules if r.type == "DOMAIN-WILDCARD"]
        self.assertEqual(len(wildcards), 1)
        self.assertEqual(wildcards[0].value, build.REGISTERED_WILDCARD)

    def test_network_test_route_assertions_isolate_category(self) -> None:
        result = candidate()
        records = [
            build.Rule(item["type"], item["value"], category)
            for category in build.SOURCE_CATEGORIES
            for item in result.manifest["outputs"][category]["rules"]
        ]
        for host in ("whatismyip.com", "speedtest.net", "ipinfo.io"):
            self.assertEqual({r.category for r in records if build.rule_matches_host(r, host)}, {"network-test"})


class HTTPResponseTests(unittest.TestCase):
    url = "https://raw.githubusercontent.com/example/repo/main/rules.list"

    def response(self, *, chunks: list[bytes], headers: dict[str, str] | None = None):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = headers or {}
        response.geturl.return_value = self.url
        response.read.side_effect = chunks
        return response

    def test_response_bytes_rejects_truncated_declared_body(self) -> None:
        response = self.response(chunks=[b"DOMAIN", b""], headers={"Content-Length": "10"})
        with mock.patch.object(build.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(build.BuildError, "does not match Content-Length 10"):
                build._response_bytes(self.url, 100)

    def test_response_bytes_collects_short_reads_until_eof_without_length(self) -> None:
        chunks = [b"DOM", b"AIN,valid.", b"example\n", b""]
        response = self.response(chunks=chunks)
        with mock.patch.object(build.urllib.request, "urlopen", return_value=response):
            self.assertEqual(build._response_bytes(self.url, 100), b"".join(chunks[:-1]))
        self.assertEqual(response.read.call_count, len(chunks))

    def test_response_bytes_rejects_unknown_length_overflow(self) -> None:
        response = self.response(chunks=[b"abc", b"def"], headers={})
        with mock.patch.object(build.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(build.BuildError, "exceeds the 5-byte limit"):
                build._response_bytes(self.url, 5)

    def test_response_bytes_rejects_invalid_or_over_limit_length_headers(self) -> None:
        for header in ("-1", "abc", "6"):
            response = self.response(chunks=[b""], headers={"Content-Length": header})
            with self.subTest(content_length=header), mock.patch.object(
                build.urllib.request, "urlopen", return_value=response
            ):
                with self.assertRaises(build.BuildError):
                    build._response_bytes(self.url, 5)
            response.read.assert_not_called()


class FetchAndUpdateTests(unittest.TestCase):
    def test_cn_direct_cannot_be_implicitly_retired_by_removing_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            copied_policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
            self.assertNotIn("cn_direct", copied_policy)

            bundle_paths = (
                set(build.OUTPUT_PATHS.values())
                | set(build.ARCHIVE_PATHS.values())
                | set(build.SURGE_DOMAIN_SET_PATHS.values())
                | build._cn_allowed_paths()
                | {
                    build.SURGE_PROCESS_RULES_PATH,
                    build.US_RULES_PATH,
                    build.SURGE_US_RULES_PATH,
                    build.DIRECT_RULES_PATH,
                    build.SURGE_DIRECT_RULES_PATH,
                    "manifest.json",
                    "upstream/provenance.json",
                    "CHECKED_AT.json",
                }
            )
            for index, relative in enumerate(sorted(bundle_paths)):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"existing bundle {index}\n".encode("utf-8"))
            before_bundle = {relative: (root / relative).read_bytes() for relative in bundle_paths}
            retained_baseline = build.Baseline(
                release_id="a" * 64,
                source_rules={},
                output_rules={},
                cn_direct={"fixture": "previously enabled"},
            )

            with mock.patch.object(build, "_read_current_baseline", return_value=retained_baseline), \
                    mock.patch.object(build, "fetch_upstream") as fetch_upstream:
                with self.assertRaisesRegex(build.BuildError, "CN-direct policy cannot be removed"):
                    build.run_update(root, "2026-10-02T00:00:00Z")

            fetch_upstream.assert_not_called()
            self.assertEqual(before_bundle, {relative: (root / relative).read_bytes() for relative in bundle_paths})

    def test_ref_fetch_pins_both_paths_to_one_full_commit_sha(self) -> None:
        sha = META_SHA_A
        calls = []

        def response(url, maximum):
            calls.append(url)
            if url == build.META_SHA_API:
                return json.dumps({"ref": "refs/heads/meta", "object": {"type": "commit", "sha": sha}}).encode()
            return b"DOMAIN,fixture.example\n"

        with mock.patch.object(build, "_response_bytes", side_effect=response):
            got_sha, sources = build.fetch_upstream()
        self.assertEqual(got_sha, sha)
        self.assertEqual(set(sources), {"global", "cn", "network-test"})
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(f"/{sha}/" in url for url in calls[1:]))

    def test_ref_fetch_rejects_a_non_commit_or_wrong_branch(self) -> None:
        for response in (
            {"ref": "refs/heads/other", "object": {"type": "commit", "sha": META_SHA_A}},
            {"ref": "refs/heads/meta", "object": {"type": "tag", "sha": META_SHA_A}},
        ):
            with mock.patch.object(build, "_response_bytes", return_value=json.dumps(response).encode()):
                with self.assertRaises(build.BuildError):
                    build.fetch_upstream()

    def test_update_and_offline_replay_write_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                result = build.run_update(root, "2026-09-26T00:00:00Z")
            self.assertEqual(result["status"], "released")
            for path in (
                *build.OUTPUT_PATHS.values(),
                *build.ARCHIVE_PATHS.values(),
                build.SURGE_PROCESS_RULES_PATH,
                build.US_RULES_PATH,
                build.SURGE_US_RULES_PATH,
                build.DIRECT_RULES_PATH,
                build.SURGE_DIRECT_RULES_PATH,
                "upstream/provenance.json",
                "manifest.json",
                "CHECKED_AT.json",
            ):
                self.assertTrue((root / path).is_file(), path)
            with mock.patch.object(build, "fetch_upstream", side_effect=AssertionError("offline validation must not fetch")):
                replay = build.run_offline_validation(root)
            self.assertEqual(replay["offline_replay"], "passed")

    def test_parse_failure_keeps_live_bundle_unchanged_and_reports_candidate_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                build.run_update(root, "2026-09-26T00:00:00Z")
            bundle_paths = [
                *build.OUTPUT_PATHS.values(),
                *build.ARCHIVE_PATHS.values(),
                build.SURGE_PROCESS_RULES_PATH,
                build.US_RULES_PATH,
                build.SURGE_US_RULES_PATH,
                build.DIRECT_RULES_PATH,
                build.SURGE_DIRECT_RULES_PATH,
                "upstream/provenance.json",
                "manifest.json",
                "CHECKED_AT.json",
            ]
            before = {path: (root / path).read_bytes() for path in bundle_paths}
            bad = fixture_sources()
            bad["cn"] = b"DOMAIN-REGEX,^unknown\\.example$\n"
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(bad, META_SHA_B)):
                with self.assertRaisesRegex(build.BuildError, "unknown or changed DOMAIN-REGEX"):
                    build.run_update(root, "2026-09-27T00:00:00Z")
            self.assertEqual(before, {path: (root / path).read_bytes() for path in bundle_paths})
            diagnostic = json.loads((root / ".build-report/result.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnostic["status"], "failed")
            self.assertEqual(diagnostic["meta_sha"], META_SHA_B)
            self.assertEqual((root / ".build-report/evidence/source-cn.list").read_bytes(), bad["cn"])

    def test_failure_fetching_second_source_keeps_first_snapshot_and_sha_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)

            def fail_second(*, on_meta_sha=None, on_source=None):
                if on_meta_sha:
                    on_meta_sha(META_SHA_A)
                if on_source:
                    on_source("global", fixture_sources()["global"])
                raise build.BuildError("simulated failure fetching cn source")

            with mock.patch.object(build, "fetch_upstream", side_effect=fail_second):
                with self.assertRaisesRegex(build.BuildError, "simulated failure"):
                    build.run_update(root, "2026-09-26T00:00:00Z")
            report = json.loads((root / ".build-report/result.json").read_text(encoding="utf-8"))
            self.assertEqual(report["meta_sha"], META_SHA_A)
            self.assertTrue((root / ".build-report/evidence/source-global.list").is_file())
            self.assertFalse((root / ".build-report/evidence/source-cn.list").exists())
            self.assertTrue((root / ".build-report/evidence/source-meta.json").is_file())
            self.assertFalse((root / "manifest.json").exists())

    def test_large_source_delta_is_published_and_offline_replay_needs_no_quantity_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            initialize_git(root)
            base_sources = fixture_sources()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(base_sources, META_SHA_A)):
                build.run_update(root, "2026-09-01T00:00:00Z")
            commit_workspace(root, "first accepted fixture release")

            changed_sources = dict(base_sources)
            changed_sources["global"] = append_rules(
                base_sources["global"], *(f"DOMAIN,new-{index}.example" for index in range(1_101))
            )
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(changed_sources, META_SHA_B)):
                accepted = build.run_update(root, "2026-09-02T00:00:00Z")
            self.assertEqual(accepted["status"], "released")
            report = json.loads((root / ".build-report/result.json").read_text(encoding="utf-8"))
            self.assertRegex(report["candidate_id"], r"^[0-9a-f]{64}$")
            self.assertEqual(len(report["diffs"]["source"]["global"]["added"]), 1_101)
            replay = build.run_offline_validation(root)
            self.assertEqual(replay["offline_replay"], "passed")

    def test_hold_blocks_bundle_changes_allows_only_due_check_and_revalidates_after_unhold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            initialize_git(root)
            original_sources = fixture_sources()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(original_sources, META_SHA_A)):
                first = build.run_update(root, "2026-09-01T00:00:00Z")
            commit_workspace(root, "first accepted fixture release")

            policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
            policy["publish_hold"] = {"enabled": True, "reason": "Rollback review.", "rolled_back_release_id": first["release_id"]}
            (root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            bundle_paths = [
                *build.OUTPUT_PATHS.values(),
                *build.ARCHIVE_PATHS.values(),
                build.SURGE_PROCESS_RULES_PATH,
                build.US_RULES_PATH,
                build.SURGE_US_RULES_PATH,
                build.DIRECT_RULES_PATH,
                build.SURGE_DIRECT_RULES_PATH,
                "upstream/provenance.json",
                "manifest.json",
            ]
            before_bundle = {path: (root / path).read_bytes() for path in bundle_paths}
            not_due_check = (root / "CHECKED_AT.json").read_bytes()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(original_sources, META_SHA_A)):
                held_not_due = build.run_update(root, "2026-09-02T00:00:00Z")
            self.assertEqual(held_not_due["status"], "validated_not_published_hold")
            self.assertEqual(before_bundle, {path: (root / path).read_bytes() for path in bundle_paths})
            self.assertEqual(not_due_check, (root / "CHECKED_AT.json").read_bytes())

            changed_sources = dict(original_sources)
            changed_sources["global"] = append_rules(original_sources["global"], "DOMAIN,new-held.example")
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(changed_sources, META_SHA_B)):
                held_due = build.run_update(root, "2026-10-02T00:00:00Z")
            self.assertEqual(held_due["status"], "validated_not_published_hold")
            self.assertTrue(held_due["checked_at_written"])
            self.assertEqual(before_bundle, {path: (root / path).read_bytes() for path in bundle_paths})
            checked = json.loads((root / "CHECKED_AT.json").read_text(encoding="utf-8"))
            self.assertEqual(checked["result"], "validated_not_published_hold")
            self.assertNotEqual(checked["candidate_id"], checked["live_release_id"])
            held_replay = build.run_offline_validation(root)
            self.assertEqual(held_replay["held_audit_candidate"], "identity-recorded-but-not-archived")

            invalid_sources = dict(changed_sources)
            invalid_sources["cn"] = b"DOMAIN-KEYWORD,unknown\n"
            prior_check = (root / "CHECKED_AT.json").read_bytes()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(invalid_sources, "c" * 40)):
                with self.assertRaises(build.BuildError):
                    build.run_update(root, "2026-10-03T00:00:00Z")
            self.assertEqual(prior_check, (root / "CHECKED_AT.json").read_bytes())

            policy["publish_hold"] = {"enabled": False, "reason": "", "rolled_back_release_id": ""}
            (root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(changed_sources, META_SHA_B)):
                unheld = build.run_update(root, "2026-10-03T00:00:00Z")
            self.assertEqual(unheld["status"], "released")
            fresh_check = json.loads((root / "CHECKED_AT.json").read_text(encoding="utf-8"))
            self.assertEqual(fresh_check["result"], "released")
            self.assertEqual(build.run_offline_validation(root)["offline_replay"], "passed")

    def test_tool_hash_uses_fixed_list_of_build_test_and_fixture_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in build.TOOL_CONTENT_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")
            first = build.tool_sha256(root)
            (root / "tests/fixtures/routes.json").write_text("changed", encoding="utf-8")
            second = build.tool_sha256(root)
            self.assertNotEqual(first, second)

    def test_archived_replay_finds_previous_release_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            initialize_git(root)
            first_sources = fixture_sources()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(first_sources, META_SHA_A)):
                first = build.run_update(root, "2026-09-01T00:00:00Z")
            commit_workspace(root, "first accepted fixture release")

            second_sources = dict(first_sources)
            second_sources["global"] = append_rules(first_sources["global"], "DOMAIN,new-archive.example")
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(second_sources, META_SHA_B)):
                second = build.run_update(root, "2026-09-02T00:00:00Z")
            self.assertEqual(second["baseline_release_id"], first["release_id"])
            commit_workspace(root, "second accepted fixture release")
            with mock.patch.object(build, "fetch_upstream", side_effect=AssertionError("offline replay contacted network")):
                self.assertEqual(build.run_offline_validation(root)["offline_replay"], "passed")


class SurgeProcessRuleTests(unittest.TestCase):
    EXPECTED_ENABLED = [
        "/Applications/ChatGPT.app/",
        "/Applications/Claude.app/",
        "claude",
        "codex",
    ]
    DOMAIN_ARTIFACTS = (
        "rules/ai-cn.list",
        "rules/ai-global.list",
        "rules/network-test.list",
        "rules/surge/ai-cn.set",
        "rules/surge/network-test.set",
        build.US_RULES_PATH,
        build.SURGE_US_RULES_PATH,
        build.DIRECT_RULES_PATH,
        build.SURGE_DIRECT_RULES_PATH,
    )

    def _policy_with(self, **over):
        policy = policy_value()
        entry = copy.deepcopy(policy["surge_process_rules"][0])
        entry.update(over)
        policy["surge_process_rules"] = [entry]
        return policy

    def test_render_outputs_header_and_enabled_rules_in_policy_order(self) -> None:
        result = candidate()
        content = result.manual_files[build.SURGE_PROCESS_RULES_PATH].decode("utf-8")
        lines = content.splitlines()
        self.assertTrue(lines[0].startswith("# Surge macOS only"))
        self.assertIn("no upstream", "\n".join(lines))
        rule_lines = [line for line in lines if not line.startswith("#")]
        self.assertEqual(rule_lines, [f"PROCESS-NAME,{value}" for value in self.EXPECTED_ENABLED])
        # The optional disabled rule must not be rendered.
        self.assertNotIn("SkyComputerUseService", content)
        self.assertTrue(content.endswith("\n"))

    def test_manifest_records_manual_artifact(self) -> None:
        result = candidate()
        entry = result.manifest["manual_artifacts"][build.SURGE_PROCESS_RULES_PATH]
        self.assertEqual(entry["rules"], 4)
        self.assertEqual(entry["source"], build.SURGE_PROCESS_RULE_SOURCE)
        self.assertEqual(entry["review_date"], "2026-09-29")
        self.assertEqual(entry["path"], build.SURGE_PROCESS_RULES_PATH)
        self.assertEqual(entry["sha256"], build.sha256(result.manual_files[build.SURGE_PROCESS_RULES_PATH]))

    def test_conservative_tier_values_are_the_four_reviewed_forms(self) -> None:
        policy = policy_value()
        conservative = [item["value"] for item in policy["surge_process_rules"] if item["tier"] == "conservative" and item["enabled"]]
        self.assertEqual(conservative, self.EXPECTED_ENABLED)

    def test_invalid_values_are_rejected(self) -> None:
        # Bundle prefix starts with '/' but must also end with '/'.
        with self.assertRaisesRegex(build.BuildError, "does not end with '/'"):
            build.validate_surge_process_rules(self._policy_with(value="/Applications/ChatGPT.app"))
        # Filename mode must not contain a path separator.
        with self.assertRaisesRegex(build.BuildError, "contains '/'"):
            build.validate_surge_process_rules(self._policy_with(value="local/bin/claude"))
        # Filename mode is restricted to a tight ASCII charset.
        for bad in ("bad;name", "bad$name", "x\\y"):
            with self.subTest(bad=bad):
                with self.assertRaises(build.BuildError):
                    build.validate_surge_process_rules(self._policy_with(value=bad))
        # Missing required field.
        missing = self._policy_with(value="okname")
        del missing["surge_process_rules"][0]["reference"]
        with self.assertRaises(build.BuildError):
            build.validate_surge_process_rules(missing)
        # Illegal tier and non-boolean enabled.
        with self.assertRaises(build.BuildError):
            build.validate_surge_process_rules(self._policy_with(value="okname", tier="nope"))
        with self.assertRaises(build.BuildError):
            build.validate_surge_process_rules(self._policy_with(value="okname", enabled="yes"))

    def test_domain_artifacts_never_contain_process_rules_and_vice_versa(self) -> None:
        generated = candidate()
        for relative in self.DOMAIN_ARTIFACTS:
            content = (
                generated.manual_files[relative].decode("utf-8")
                if relative in generated.manual_files
                else (ROOT / relative).read_text(encoding="utf-8")
            )
            for line in content.splitlines():
                self.assertFalse(line.startswith("PROCESS-NAME,"), relative)
        process = candidate().manual_files[build.SURGE_PROCESS_RULES_PATH].decode("utf-8")
        for token in ("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-WILDCARD,"):
            self.assertNotIn(token, process)

    def test_case_sensitive_filename_and_bundle_prefix_exactness(self) -> None:
        process = candidate().manual_files[build.SURGE_PROCESS_RULES_PATH].decode("utf-8")
        self.assertIn("PROCESS-NAME,claude\n", process)
        self.assertIn("PROCESS-NAME,codex\n", process)
        self.assertNotIn("PROCESS-NAME,Claude", process)
        self.assertNotIn(".exe", process)
        self.assertIn("PROCESS-NAME,/Applications/ChatGPT.app/", process)
        self.assertIn("PROCESS-NAME,/Applications/Claude.app/", process)

    def test_offline_replay_writes_and_rechecks_ai_process_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                result = build.run_update(root, "2026-09-26T00:00:00Z")
            self.assertEqual(result["status"], "released")
            written = (root / build.SURGE_PROCESS_RULES_PATH).read_bytes()
            self.assertIn("PROCESS-NAME,claude", written.decode("utf-8"))
            self.assertNotIn("SkyComputerUseService", written.decode("utf-8"))
            with mock.patch.object(build, "fetch_upstream", side_effect=AssertionError("offline validation must not fetch")):
                replay = build.run_offline_validation(root)
            self.assertEqual(replay["offline_replay"], "passed")

    def test_tampering_ai_process_list_breaks_offline_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                build.run_update(root, "2026-09-26T00:00:00Z")
            target = root / build.SURGE_PROCESS_RULES_PATH
            target.write_bytes(target.read_bytes() + b"PROCESS-NAME,node\n")
            with self.assertRaisesRegex(build.BuildError, "ai-process.list differs"):
                build.run_offline_validation(root)


class USRuleTests(unittest.TestCase):
    EXPECTED_DOMAINS = [
        "sentitlement2.mobile.att.net",
        "epdg.epc.att.net",
        "epdg.epc.att-idns.net",
    ]

    def test_us_rules_are_exact_and_render_surge_domain_set_without_prefix_dots(self) -> None:
        policy = policy_value()
        result = candidate(policy=policy)

        self.assertEqual(build.SOURCE_CATEGORIES, ("global", "cn", "network-test"))
        self.assertEqual(set(result.manifest["outputs"]), set(build.SOURCE_CATEGORIES))
        us_text = result.manual_files[build.US_RULES_PATH].decode("utf-8")
        us_rules = [line for line in us_text.splitlines() if line and not line.startswith("#")]
        self.assertEqual(us_rules, [f"DOMAIN,{domain}" for domain in self.EXPECTED_DOMAINS])
        surge_text = result.manual_files[build.SURGE_US_RULES_PATH].decode("utf-8")
        self.assertEqual(surge_text.splitlines(), self.EXPECTED_DOMAINS)
        self.assertTrue(surge_text.endswith("\n"))

        for path in (build.US_RULES_PATH, build.SURGE_US_RULES_PATH):
            entry = result.manifest["manual_artifacts"][path]
            self.assertEqual(entry["path"], path)
            self.assertEqual(entry["rules"], 3)
            self.assertEqual(entry["source"], build.US_RULE_SOURCE)
            self.assertEqual(entry["review_date"], "2026-10-18")
            self.assertEqual(entry["sha256"], build.sha256(result.manual_files[path]))

    def test_invalid_us_policy_entries_are_rejected(self) -> None:
        mutations = (
            lambda p: p["us_rules"].append(copy.deepcopy(p["us_rules"][0])),
            lambda p: p["us_rules"][0].update(type="DOMAIN-KEYWORD"),
            lambda p: p["us_rules"][0].update(value="Sentitlement2.mobile.att.net"),
            lambda p: p["us_rules"][0].pop("reference"),
            lambda p: p["us_rules"][0].update(review_date="2026-13-40"),
            lambda p: p["us_rules"][0].update(unreviewed=True),
            lambda p: p.update(us_rules=[]),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                policy = policy_value()
                mutation(policy)
                with self.assertRaises(build.BuildError):
                    build.validate_us_rules(policy)

    def test_review_metadata_is_bound_to_release_identity(self) -> None:
        original = candidate()
        changed_policy = policy_value()
        changed_policy["us_rules"][0]["reference"] += "; amended review note"
        changed = candidate(policy=changed_policy)

        self.assertNotEqual(original.release_id, changed.release_id)
        self.assertNotEqual(
            original.manifest["semantic_policy_sha256"],
            changed.manifest["semantic_policy_sha256"],
        )

    def test_update_writes_us_artifacts_and_offline_replay_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                result = build.run_update(root, "2026-10-18T00:00:00Z")
            self.assertEqual(result["status"], "released")
            self.assertEqual(
                (root / build.SURGE_US_RULES_PATH).read_text(encoding="utf-8").splitlines(),
                self.EXPECTED_DOMAINS,
            )
            with mock.patch.object(build, "fetch_upstream", side_effect=AssertionError("offline validation must not fetch")):
                replay = build.run_offline_validation(root)
            self.assertEqual(replay["offline_replay"], "passed")

            target = root / build.SURGE_US_RULES_PATH
            target.write_bytes(target.read_bytes() + b"tampered.example\n")
            with self.assertRaisesRegex(build.BuildError, "rules/surge/us.set differs from offline replay"):
                build.run_offline_validation(root)


class DirectRuleTests(unittest.TestCase):
    def test_direct_rules_are_canonical_manual_artifacts_bound_to_release_identity(self) -> None:
        policy = policy_value()
        keys = [(item["type"], item["value"]) for item in policy["direct_rules"]]
        self.assertEqual(keys, sorted(set(keys)))
        result = candidate(policy=policy)

        direct_text = result.manual_files[build.DIRECT_RULES_PATH].decode("utf-8")
        direct_lines = [line for line in direct_text.splitlines() if line and not line.startswith("#")]
        self.assertEqual(direct_lines, [f"{item['type']},{item['value']}" for item in policy["direct_rules"]])
        surge_text = result.manual_files[build.SURGE_DIRECT_RULES_PATH].decode("utf-8")
        expected_surge = [
            ("." + item["value"] if item["type"] == "DOMAIN-SUFFIX" else item["value"])
            for item in policy["direct_rules"]
        ]
        self.assertEqual(surge_text.splitlines(), expected_surge)
        self.assertEqual(len(direct_lines), 25)
        self.assertEqual(sum(item["type"] == "DOMAIN" for item in policy["direct_rules"]), 10)
        self.assertEqual(sum(item["type"] == "DOMAIN-SUFFIX" for item in policy["direct_rules"]), 15)

        for path in (build.DIRECT_RULES_PATH, build.SURGE_DIRECT_RULES_PATH):
            artifact = result.manifest["manual_artifacts"][path]
            self.assertEqual(artifact["source"], build.DIRECT_RULE_SOURCE)
            self.assertEqual(artifact["rules"], 25)
            self.assertEqual(artifact["review_date"], "2026-10-21")
            self.assertEqual(artifact["sha256"], build.sha256(result.manual_files[path]))

        changed_policy = copy.deepcopy(policy)
        changed_policy["direct_rules"][0]["reason"] += " Policy annotation changed."
        changed = candidate(policy=changed_policy)
        self.assertNotEqual(result.manifest["semantic_policy_sha256"], changed.manifest["semantic_policy_sha256"])
        self.assertNotEqual(result.release_id, changed.release_id)
        self.assertEqual(
            result.manual_files[build.DIRECT_RULES_PATH],
            changed.manual_files[build.DIRECT_RULES_PATH],
        )

        changed_policy = copy.deepcopy(policy)
        changed_policy["direct_rules"].append({
            "type": "DOMAIN",
            "value": "new-direct.example.test",
            "reason": "Reviewed direct host.",
            "reference": "https://example.test/direct",
            "review_date": "2026-10-21",
        })
        changed_scope = candidate(policy=changed_policy)
        self.assertNotEqual(result.release_id, changed_scope.release_id)
        self.assertNotEqual(
            result.manifest["manual_artifacts"][build.DIRECT_RULES_PATH]["sha256"],
            changed_scope.manifest["manual_artifacts"][build.DIRECT_RULES_PATH]["sha256"],
        )

    def test_invalid_direct_policy_entries_are_rejected(self) -> None:
        mutations = (
            lambda p: p["direct_rules"].append(copy.deepcopy(p["direct_rules"][0])),
            lambda p: p["direct_rules"][0].update(type="DOMAIN-KEYWORD"),
            lambda p: p["direct_rules"][0].update(type="DOMAIN-WILDCARD"),
            lambda p: p["direct_rules"][0].update(value="Upper.example"),
            lambda p: p["direct_rules"][0].pop("reference"),
            lambda p: p["direct_rules"][0].update(review_date="2026-13-40"),
            lambda p: p.update(direct_rules=[]),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                policy = policy_value()
                mutation(policy)
                with self.assertRaises(build.BuildError):
                    build.validate_direct_rules(policy)

    def test_direct_suffixes_reject_single_labels_and_public_suffixes_before_baseline_coverage(self) -> None:
        covered_baseline = build.Baseline(
            release_id="1" * 64,
            source_rules={category: [] for category in build.SOURCE_CATEGORIES},
            output_rules={
                "global": [],
                "cn": [("DOMAIN-SUFFIX", "cn")],
                "network-test": [],
            },
        )
        for value in ("cn", "com.cn"):
            policy = policy_value()
            policy["direct_rules"][0].update(type="DOMAIN-SUFFIX", value=value)
            for label, baseline in (("bootstrap", None), ("already-covered", covered_baseline)):
                with self.subTest(value=value, baseline=label):
                    with self.assertRaisesRegex(build.BuildError, "single-label|public-suffix"):
                        candidate(policy=policy, baseline=baseline)

    def test_network_test_rules_overlapping_direct_are_removed_without_expanding_direct_scope(self) -> None:
        policy = policy_value()
        policy["direct_rules"] = [
            {
                "type": "DOMAIN",
                "value": "api.exact-direct.example.test",
                "reason": "Exact fixture selector.",
                "reference": "https://example.test/exact",
                "review_date": "2026-10-21",
            },
            {
                "type": "DOMAIN-SUFFIX",
                "value": "checks.example.test",
                "reason": "Suffix fixture selector.",
                "reference": "https://example.test/checks",
                "review_date": "2026-10-21",
            },
        ]
        sources = fixture_sources()
        sources["network-test"] = append_rules(
            sources["network-test"],
            "DOMAIN,api.exact-direct.example.test",
            "DOMAIN,sub.api.exact-direct.example.test",
            "DOMAIN,checks.example.test",
            "DOMAIN,host.checks.example.test",
            "DOMAIN-SUFFIX,checks.example.test",
            "DOMAIN-SUFFIX,example.test",
            "DOMAIN,host.unrelated.example.test",
            "DOMAIN-SUFFIX,unrelated.example.test",
        )
        result = candidate(sources, policy=policy)
        network_rules = {
            (item["type"], item["value"])
            for item in result.manifest["outputs"]["network-test"]["rules"]
        }
        for removed in (
            ("DOMAIN", "api.exact-direct.example.test"),
            ("DOMAIN", "checks.example.test"),
            ("DOMAIN", "host.checks.example.test"),
            ("DOMAIN-SUFFIX", "checks.example.test"),
            ("DOMAIN-SUFFIX", "example.test"),
        ):
            self.assertNotIn(removed, network_rules)
        for retained in (
            ("DOMAIN", "sub.api.exact-direct.example.test"),
            ("DOMAIN", "host.unrelated.example.test"),
            ("DOMAIN-SUFFIX", "unrelated.example.test"),
        ):
            self.assertIn(retained, network_rules)

        exclusions = result.manifest["direct_rule_exclusions"]
        parent = next(item for item in exclusions if item["value"] == "example.test")
        self.assertEqual(parent["decision"], "partial_overlap_parent_omitted")
        self.assertEqual(parent["selectors"], [
            {"type": "DOMAIN", "value": "api.exact-direct.example.test"},
            {"type": "DOMAIN-SUFFIX", "value": "checks.example.test"},
        ])
        self.assertTrue(any(
            origin.get("kind") == "meta"
            and origin.get("raw") == "DOMAIN-SUFFIX,example.test"
            and origin.get("path") == build._source_path_list("network-test")[0]
            for origin in parent["origins"]
        ))
        self.assertIn(
            {"type": "DOMAIN-SUFFIX", "value": "example.test"},
            result.manifest["normalized_source"]["network-test"],
        )
        direct_lines = [
            line for line in result.manual_files[build.DIRECT_RULES_PATH].decode().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(direct_lines, [
            "DOMAIN,api.exact-direct.example.test",
            "DOMAIN-SUFFIX,checks.example.test",
        ])

    def test_offline_replay_detects_corrupt_direct_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(fixture_sources(), META_SHA_A)):
                build.run_update(root, "2026-10-21T00:00:00Z")

            for relative in (build.DIRECT_RULES_PATH, build.SURGE_DIRECT_RULES_PATH):
                target = root / relative
                original = target.read_bytes()
                target.write_bytes(original + b"tampered.example\n")
                with self.subTest(path=relative), self.assertRaisesRegex(build.BuildError, relative):
                    build.run_offline_validation(root)
                target.write_bytes(original)

            self.assertEqual(build.run_offline_validation(root)["offline_replay"], "passed")


if __name__ == "__main__":
    unittest.main()
