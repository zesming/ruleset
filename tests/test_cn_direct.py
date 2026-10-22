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


class CnDirectHTTPResponseTests(unittest.TestCase):
    url = "https://raw.githubusercontent.com/example/repo/main/china-max-domain.txt"

    def response(
        self,
        *,
        chunks: list[bytes],
        headers: dict[str, str] | None = None,
        url: str | None = None,
    ):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = headers or {}
        response.geturl.return_value = url or self.url
        response.read.side_effect = chunks
        return response

    def test_http_bytes_authenticates_only_canonical_github_api_urls(self) -> None:
        cases = (
            ("https://api.github.com/repos/example/repo", "Bearer test-token"),
            ("https://api.github.com:443/repos/example/repo", "Bearer test-token"),
            (self.url, None),
            ("https://ruleset-mirror.skk.moe/sukka/direct.txt", None),
            ("https://user@api.github.com/repos/example/repo", None),
            ("https://api.github.com:444/repos/example/repo", None),
        )
        with mock.patch.dict(cn_direct.os.environ, {"GITHUB_TOKEN": "test-token"}):
            for url, expected_authorization in cases:
                response = self.response(chunks=[b"ok", b""], url=url)
                with self.subTest(url=url), mock.patch.object(
                    cn_direct.urllib.request, "urlopen", return_value=response
                ) as urlopen:
                    self.assertEqual(cn_direct._http_bytes(url, 100), b"ok")
                request = urlopen.call_args.args[0]
                self.assertEqual(request.get_header("Authorization"), expected_authorization)

    def test_http_bytes_leaves_github_api_anonymous_without_token(self) -> None:
        url = "https://api.github.com/repos/example/repo"
        response = self.response(chunks=[b"ok", b""], url=url)
        with mock.patch.dict(cn_direct.os.environ, {"GITHUB_TOKEN": ""}), mock.patch.object(
            cn_direct.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            self.assertEqual(cn_direct._http_bytes(url, 100), b"ok")
        request = urlopen.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))

    def test_http_bytes_redirect_does_not_forward_unredirected_authorization(self) -> None:
        url = "https://api.github.com/repos/example/repo"
        response = self.response(chunks=[b"ok", b""], url=url)
        with mock.patch.dict(cn_direct.os.environ, {"GITHUB_TOKEN": "test-token"}), mock.patch.object(
            cn_direct.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            cn_direct._http_bytes(url, 100)
        request = urlopen.call_args.args[0]
        redirected = cn_direct.urllib.request.HTTPRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "https://api.github.com/repos/redirected/repo"
        )
        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_http_bytes_rejects_truncated_declared_body(self) -> None:
        response = self.response(chunks=[b"DOMAIN", b""], headers={"Content-Length": "10"})
        with mock.patch.object(cn_direct.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(cn_direct.CnDirectError, "does not match Content-Length 10"):
                cn_direct._http_bytes(self.url, 100)

    def test_http_bytes_collects_short_reads_until_eof_without_length(self) -> None:
        chunks = [b"DOM", b"AIN,valid.", b"example\n", b""]
        response = self.response(chunks=chunks)
        with mock.patch.object(cn_direct.urllib.request, "urlopen", return_value=response):
            self.assertEqual(cn_direct._http_bytes(self.url, 100), b"".join(chunks[:-1]))
        self.assertEqual(response.read.call_count, len(chunks))

    def test_http_bytes_rejects_unknown_length_overflow(self) -> None:
        response = self.response(chunks=[b"abc", b"def"], headers={})
        with mock.patch.object(cn_direct.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(cn_direct.CnDirectError, "exceeds 5 bytes"):
                cn_direct._http_bytes(self.url, 5)

    def test_http_bytes_rejects_invalid_or_over_limit_length_headers(self) -> None:
        for header in ("-1", "abc", "6"):
            response = self.response(chunks=[b""], headers={"Content-Length": header})
            with self.subTest(content_length=header), mock.patch.object(
                cn_direct.urllib.request, "urlopen", return_value=response
            ):
                with self.assertRaises(cn_direct.CnDirectError):
                    cn_direct._http_bytes(self.url, 5)
            response.read.assert_not_called()


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

    def test_every_cn_source_must_parse_at_least_one_rule(self) -> None:
        original = fixture_sources()
        policy = self.small_policy(original)
        empty_payloads = (b"\n", b"# comment only\n")
        for source in cn_direct.SOURCE_ORDER:
            for payload in empty_payloads:
                changed = dict(original)
                changed[source] = payload
                with self.subTest(source=source, payload=payload):
                    with self.assertRaisesRegex(cn_direct.CnDirectError, f"{source} source contains no rules"):
                        cn_direct.parse_sources(changed, policy)

            changed = dict(original)
            changed[source] = b" \n"
            with self.subTest(source=source, payload="whitespace"):
                with self.assertRaises(cn_direct.CnDirectError):
                    cn_direct.parse_sources(changed, policy)

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
        accepted_scopes = {(item["type"], item["value"]) for item in candidate.accepted_domain_rules}
        self.assertNotIn(("DOMAIN-SUFFIX", "held.example"), accepted_scopes)
        self.assertNotIn(("DOMAIN-SUFFIX", "unreviewed.example"), accepted_scopes)
        self.assertTrue(all({"source", "line", "raw"} <= item.keys() for item in candidate.accepted_domain_rules))

        removed_policy = copy.deepcopy(policy)
        removed_policy["removes"] = [{
            "type": "DOMAIN-SUFFIX",
            "value": "example.com",
            "reason": "Fixture removal before coverage indexing.",
            "evidence": "Fixture source and generated record.",
            "review_date": "2026-10-09",
        }]
        with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            removed_candidate = cn_direct.build_candidate(raw, removed_policy, baseline=baseline, converter_path="unused")
        removed_scopes = {(item["type"], item["value"]) for item in removed_candidate.accepted_domain_rules}
        self.assertNotIn(("DOMAIN-SUFFIX", "example.com"), removed_scopes)
        self.assertNotIn(("DOMAIN", "www.example.com"), removed_scopes)

        meta_sources = {
            "global": (ROOT / "tests/fixtures/source-global.list").read_bytes() + b"DOMAIN-SUFFIX,unreviewed.example\n",
            "cn": (ROOT / "tests/fixtures/source-cn.list").read_bytes(),
            "network-test": (ROOT / "tests/fixtures/source-network-test.list").read_bytes(),
        }
        meta_policy = build.validate_policy(ROOT)
        license_record, license_hash = build.license_snapshot(ROOT, meta_policy)
        meta_candidate = build.build_candidate(
            raw_sources=meta_sources,
            meta_sha="a" * 40,
            policy=meta_policy,
            license_record=license_record,
            license_hash=license_hash,
            baseline=None,
            current_tool_hash="f" * 64,
            cn_direct_candidate=candidate,
        )
        global_scopes = {(item["type"], item["value"]) for item in meta_candidate.manifest["outputs"]["global"]["rules"]}
        self.assertIn(("DOMAIN-SUFFIX", "unreviewed.example"), global_scopes)

        build_baseline = build.Baseline("a" * 64, {}, {}, baseline)
        with mock.patch.dict("os.environ", {"MIHOMO_CONVERTER": "unused"}), \
                mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            with self.assertRaisesRegex(build.BuildError, "CN-direct candidate requires review"):
                build._build_cn_candidate(
                    {"cn_direct": policy, "direct_rules": build.validate_policy(ROOT)["direct_rules"]},
                    build_baseline,
                    raw,
                    self.source_metadata(raw),
                )

    def test_redundant_acl_requires_explicit_accept_for_narrow_routing_evidence(self) -> None:
        def direct_candidate(
            base_suffix: str,
            action: str | None,
            *,
            acl_scope: str = "vendor.cn",
            decision_value: str | None = None,
            include_acl: bool = True,
        ):
            raw = fixture_sources()
            raw["china_max"] += f".{base_suffix}\n".encode("ascii")
            if include_acl:
                raw["acl_china_domain"] += f"DOMAIN-SUFFIX,{acl_scope}\n".encode("ascii")
            policy = self.small_policy(raw)
            if action is not None:
                policy["acl_review"]["decisions"].append({
                    "type": "DOMAIN-SUFFIX",
                    "value": decision_value or acl_scope,
                    "action": action,
                    "reason": "Fixture decision for a redundant ACL scope.",
                    "evidence": "The broad base scope already covers the ACL record.",
                    "review_date": "2026-10-09",
                })
            baseline = self.fixture_baseline(raw, policy)
            converter = self.converter_result(
                policy,
                b"fixture-mrs",
                {"platform": "test", "binary_sha256": "b" * 64},
            )
            with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
                result = cn_direct.build_candidate(raw, policy, baseline=baseline, converter_path="unused")
            return result

        meta_sources = {
            "global": (ROOT / "tests/fixtures/source-global.list").read_bytes(),
            "cn": (ROOT / "tests/fixtures/source-cn.list").read_bytes(),
            "network-test": (ROOT / "tests/fixtures/source-network-test.list").read_bytes(),
        }
        meta_policy = build.validate_policy(ROOT)
        license_record, license_hash = build.license_snapshot(ROOT, meta_policy)

        def build_meta_candidate(direct, ai_scope: str = "vendor.cn"):
            sources = dict(meta_sources)
            sources["global"] += f"DOMAIN-SUFFIX,{ai_scope}\n".encode("ascii")
            return build.build_candidate(
                raw_sources=sources,
                meta_sha="a" * 40,
                policy=meta_policy,
                license_record=license_record,
                license_hash=license_hash,
                baseline=None,
                current_tool_hash="f" * 64,
                cn_direct_candidate=direct,
            )

        broad_without_acl = direct_candidate("cn", None, include_acl=False)
        broad_outputs = broad_without_acl.outputs
        broad_vendor = ("DOMAIN-SUFFIX", "vendor.cn")
        for action in (None, "candidate", "reject", "accept"):
            with self.subTest(base="cn", action=action or "unreviewed"):
                direct = direct_candidate("cn", action)
                # The ACL line is redundant beneath `.cn`, so routing review
                # decisions cannot change any of the seven client artifacts.
                self.assertEqual(direct.outputs, broad_outputs)
                acl_evidence = [
                    item for item in direct.accepted_domain_rules
                    if item["source"] == "acl_china_domain" and item["value"] == "vendor.cn"
                ]
                self.assertEqual(bool(acl_evidence), action == "accept")

                result = build_meta_candidate(direct)
                global_rules = {
                    (item["type"], item["value"])
                    for item in result.manifest["outputs"]["global"]["rules"]
                }
                cn_rules = {
                    (item["type"], item["value"])
                    for item in result.manifest["outputs"]["cn"]["rules"]
                }
                if action == "accept":
                    self.assertNotIn(broad_vendor, global_rules)
                    self.assertIn(broad_vendor, cn_rules)
                else:
                    self.assertIn(broad_vendor, global_rules)
                    self.assertNotIn(broad_vendor, cn_rules)

        psl_wide_accept = direct_candidate("cn", "accept", decision_value="cn")
        psl_wide_acl = [
            item for item in psl_wide_accept.accepted_domain_rules
            if item["source"] == "acl_china_domain" and item["value"] == "vendor.cn"
        ]
        self.assertEqual(psl_wide_acl, [])
        self.assertEqual(psl_wide_accept.outputs, broad_outputs)
        psl_wide_result = build_meta_candidate(psl_wide_accept)
        self.assertIn(
            broad_vendor,
            {(item["type"], item["value"]) for item in psl_wide_result.manifest["outputs"]["global"]["rules"]},
        )

        inherited_accept = direct_candidate(
            "cn",
            "accept",
            acl_scope="api.vendor.cn",
            decision_value="vendor.cn",
        )
        inherited_acl = [
            item for item in inherited_accept.accepted_domain_rules
            if item["source"] == "acl_china_domain" and item["value"] == "api.vendor.cn"
        ]
        self.assertEqual(len(inherited_acl), 1)
        self.assertEqual(inherited_accept.outputs, broad_outputs)
        inherited_result = build_meta_candidate(inherited_accept, ai_scope="api.vendor.cn")
        inherited_rule = ("DOMAIN-SUFFIX", "api.vendor.cn")
        self.assertNotIn(
            inherited_rule,
            {(item["type"], item["value"]) for item in inherited_result.manifest["outputs"]["global"]["rules"]},
        )
        self.assertIn(
            inherited_rule,
            {(item["type"], item["value"]) for item in inherited_result.manifest["outputs"]["cn"]["rules"]},
        )

        qualified_base = direct_candidate("vendor.cn", None)
        qualified_evidence = [
            item for item in qualified_base.accepted_domain_rules
            if item["value"] == "vendor.cn"
        ]
        self.assertEqual({item["source"] for item in qualified_evidence}, {"china_max"})
        qualified_result = build_meta_candidate(qualified_base)
        self.assertNotIn(
            broad_vendor,
            {(item["type"], item["value"]) for item in qualified_result.manifest["outputs"]["global"]["rules"]},
        )
        self.assertIn(
            broad_vendor,
            {(item["type"], item["value"]) for item in qualified_result.manifest["outputs"]["cn"]["rules"]},
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
        self.assertNotIn("quantity_errors", candidate.manifest)
        self.assertEqual(candidate.manifest["semantic_review_errors"], [])
        self.assertEqual(candidate.unreviewed_candidates, [])

    def test_explicit_direct_rules_join_the_cn_merge_before_compression(self) -> None:
        raw = fixture_sources()
        policy = self.small_policy(raw)
        direct_rules = [
            {
                "type": "DOMAIN",
                "value": "host.direct-api.example.org",
                "reason": "Reviewed exact host.",
                "reference": "https://example.test/api",
                "review_date": "2026-10-21",
            },
            {
                "type": "DOMAIN-SUFFIX",
                "value": "direct-scope.example.org",
                "reason": "Reviewed suffix scope.",
                "reference": "https://example.test/scope",
                "review_date": "2026-10-21",
            },
        ]
        baseline = self.fixture_baseline(raw, policy)
        converter = self.converter_result(
            policy,
            b"fixture-mrs",
            {"platform": "test", "binary_sha256": "b" * 64},
        )
        with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            result = cn_direct.build_candidate(
                raw,
                policy,
                baseline=baseline,
                converter_path="unused",
                explicit_direct_rules=direct_rules,
            )

        scopes = {(item["type"], item["value"]) for item in result.domain_rules}
        self.assertIn(("DOMAIN", "host.direct-api.example.org"), scopes)
        self.assertIn(("DOMAIN-SUFFIX", "direct-scope.example.org"), scopes)
        accepted = [item for item in result.accepted_domain_rules if item["source"] == "policy.direct_rules"]
        self.assertEqual({(item["type"], item["value"]) for item in accepted}, {
            ("DOMAIN", "host.direct-api.example.org"),
            ("DOMAIN-SUFFIX", "direct-scope.example.org"),
        })
        self.assertTrue(all(item["review_date"] == "2026-10-21" for item in accepted))
        origins = {item["value"]: item for item in result.manifest["rule_origins"]}
        self.assertEqual(
            origins["direct-scope.example.org"]["source_rule_counts"]["policy.direct_rules"],
            1,
        )

        invalid = copy.deepcopy(direct_rules)
        invalid[0]["type"] = "DOMAIN-KEYWORD"
        with self.assertRaisesRegex(cn_direct.CnDirectError, "must be DOMAIN or DOMAIN-SUFFIX"):
            cn_direct.build_candidate(raw, policy, baseline=baseline, converter_path="unused", explicit_direct_rules=invalid)

        covered_baseline = {
            "source_rules": {},
            "domain_rules": [{"type": "DOMAIN-SUFFIX", "value": "cn"}],
        }
        for value, message in (
            ("cn", "single-label"),
            ("com.cn", "public-suffix"),
        ):
            invalid_scope = [{
                "type": "DOMAIN-SUFFIX",
                "value": value,
                "reason": "Deliberately broad test selector.",
                "reference": "https://example.test/broad",
                "review_date": "2026-10-21",
            }]
            for label, direct_baseline in (("bootstrap", None), ("already-covered", covered_baseline)):
                with self.subTest(value=value, baseline=label):
                    with self.assertRaisesRegex(cn_direct.CnDirectError, message):
                        cn_direct.build_candidate(
                            raw,
                            policy,
                            baseline=direct_baseline,
                            converter_path="unused",
                            explicit_direct_rules=invalid_scope,
                        )

    def test_large_source_and_delta_are_unbounded_by_removed_rule_percentages(self) -> None:
        original = fixture_sources()
        policy = self.small_policy(original)
        baseline = self.fixture_baseline(original, policy)
        additions = "".join(
            f"DOMAIN-SUFFIX,large-{index}.example.org\n"
            for index in range(10_001)
        ).encode("ascii")
        changed = dict(original)
        changed["sukka_direct_clash"] += additions
        changed["sukka_direct_surge"] += additions
        converter = self.converter_result(
            policy,
            b"fixture-mrs",
            {"platform": "test", "binary_sha256": "b" * 64},
        )
        with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            result = cn_direct.build_candidate(changed, policy, baseline=baseline, converter_path="unused")

        self.assertEqual(result.manifest["diffs"]["sources"]["sukka_direct_clash"]["added"], 10_001)
        self.assertEqual(result.manifest["diffs"]["domain_output"]["added"], 10_001)
        self.assertGreater(len(result.domain_rules), 10_000)
        self.assertEqual(result.manifest["semantic_review_errors"], [])
        self.assertNotIn("quantity_errors", result.manifest)

    def test_cn_direct_byte_and_format_guards_remain(self) -> None:
        raw = fixture_sources()
        policy = self.small_policy(raw)
        policy["sources"]["china_max"]["max_bytes"] = len(raw["china_max"]) - 1
        with self.assertRaisesRegex(cn_direct.CnDirectError, "exceeds its policy byte limit"):
            cn_direct.parse_sources(raw, policy)
        with self.assertRaisesRegex(cn_direct.CnDirectError, "unknown Sukka source type"):
            cn_direct._parse_sukka(b"UNKNOWN,value\n", "fixture", 1024)

    def test_new_broad_scopes_remain_semantic_review_errors(self) -> None:
        raw = fixture_sources()
        original = dict(raw)
        original["china_max"] += b".a.example.org\n"
        policy = self.small_policy(original)
        baseline = self.fixture_baseline(original, policy)
        changed = dict(original)
        changed["china_max"] += b".example.org\n.com\n"
        converter = self.converter_result(
            policy,
            b"fixture-mrs",
            {"platform": "test", "binary_sha256": "b" * 64},
        )
        with mock.patch.object(cn_direct, "_convert_mrs", return_value=converter):
            result = cn_direct.build_candidate(
                changed,
                policy,
                baseline=baseline,
                converter_path="unused",
            )
        self.assertEqual(
            result.manifest["semantic_review_errors"],
            [
                "new broad cn-direct merged suffix requires review: com",
                "new broad cn-direct merged suffix requires review: example.org",
            ],
        )
        self.assertEqual(result.manifest["wide_scope_review_candidates"], [
            {"type": "DOMAIN-SUFFIX", "value": "com"},
            {"type": "DOMAIN-SUFFIX", "value": "example.org"},
        ])


if __name__ == "__main__":
    unittest.main()
