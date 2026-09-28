from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
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
    shutil.copy2(ROOT / "scripts/build.py", root / "scripts/build.py")
    shutil.copy2(ROOT / "tests/test_build.py", root / "tests/test_build.py")
    for name in ("source-cn.list", "source-global.list", "routes.json"):
        shutil.copy2(ROOT / "tests/fixtures" / name, root / "tests/fixtures" / name)
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

    def test_quantity_gate_reports_stable_candidate_and_exact_approval_bypasses_only_quantity(self) -> None:
        first = candidate()
        baseline = baseline_from(first)
        new_sources = fixture_sources()
        new_sources["global"] = append_rules(new_sources["global"], *(f"DOMAIN,new-{index}.example" for index in range(11)))
        policy = policy_value()
        rejected = candidate(new_sources, policy=policy, baseline=baseline, meta_sha=META_SHA_B)
        self.assertTrue(rejected.quantity_errors)
        with self.assertRaisesRegex(build.BuildError, rejected.candidate_id):
            build.enforce_quantity_gate(rejected, policy)
        policy["quantity_approvals"] = [{"candidate_id": rejected.candidate_id, "reason": "Reviewed source change.", "approved_on": "2026-09-26"}]
        approved = candidate(new_sources, policy=policy, baseline=baseline, meta_sha=META_SHA_B)
        self.assertEqual(rejected.candidate_id, approved.candidate_id)
        build.enforce_quantity_gate(approved, policy)
        self.assertTrue(approved.quantity_errors)

    def test_additions_and_removals_are_gated_separately_even_at_net_zero(self) -> None:
        sources = fixture_sources()
        filler = [f"DOMAIN,old-{index}.example" for index in range(20)]
        sources["global"] = append_rules(sources["global"], *filler)
        first = candidate(sources)
        baseline = baseline_from(first)
        changed = remove_rule(sources["global"], "DOMAIN,old-0.example")
        for index in range(1, 11):
            changed = remove_rule(changed, f"DOMAIN,old-{index}.example")
        changed = append_rules(changed, *(f"DOMAIN,new-{index}.example" for index in range(11)))
        changed_sources = {**sources, "global": changed}
        result = candidate(changed_sources, baseline=baseline, meta_sha=META_SHA_B)
        self.assertEqual(len(result.manifest["diffs"]["source"]["global"]["added"]), 11)
        self.assertEqual(len(result.manifest["diffs"]["source"]["global"]["removed"]), 11)
        self.assertGreaterEqual(len(result.quantity_errors), 2)

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


class FetchAndUpdateTests(unittest.TestCase):
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
        self.assertEqual(set(sources), {"global", "cn"})
        self.assertEqual(len(calls), 3)
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
            for path in (*build.OUTPUT_PATHS.values(), *build.ARCHIVE_PATHS.values(), "upstream/provenance.json", "manifest.json", "CHECKED_AT.json"):
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
            bundle_paths = [*build.OUTPUT_PATHS.values(), *build.ARCHIVE_PATHS.values(), "upstream/provenance.json", "manifest.json", "CHECKED_AT.json"]
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

    def test_quantity_failure_report_has_exact_candidate_and_diff_then_exact_approval_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepare_temp_root(root)
            initialize_git(root)
            base_sources = fixture_sources()
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(base_sources, META_SHA_A)):
                build.run_update(root, "2026-09-01T00:00:00Z")
            commit_workspace(root, "first accepted fixture release")

            changed_sources = dict(base_sources)
            changed_sources["global"] = append_rules(base_sources["global"], *(f"DOMAIN,new-{index}.example" for index in range(11)))
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(changed_sources, META_SHA_B)):
                with self.assertRaisesRegex(build.BuildError, "Quantity gate rejected candidate"):
                    build.run_update(root, "2026-09-02T00:00:00Z")
            report = json.loads((root / ".build-report/result.json").read_text(encoding="utf-8"))
            self.assertRegex(report["candidate_id"], r"^[0-9a-f]{64}$")
            self.assertEqual(len(report["diffs"]["source"]["global"]["added"]), 11)
            self.assertTrue(report["quantity_gate_errors"])

            policy = json.loads((root / "policy.json").read_text(encoding="utf-8"))
            policy["quantity_approvals"].append({
                "candidate_id": report["candidate_id"],
                "reason": "Reviewed fixture source change.",
                "approved_on": "2026-09-02",
            })
            (root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            with mock.patch.object(build, "fetch_upstream", side_effect=source_runner(changed_sources, META_SHA_B)):
                accepted = build.run_update(root, "2026-09-02T01:00:00Z")
            self.assertEqual(accepted["status"], "released")
            self.assertEqual(accepted["candidate_id"], report["candidate_id"])

            policy["quantity_approvals"] = []
            (root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
            bundle_paths = [*build.OUTPUT_PATHS.values(), *build.ARCHIVE_PATHS.values(), "upstream/provenance.json", "manifest.json"]
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


if __name__ == "__main__":
    unittest.main()
