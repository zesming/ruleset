from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import personal_profile  # noqa: E402


def profile_value() -> dict:
    return json.loads((ROOT / personal_profile.PROFILE_PATH).read_text(encoding="utf-8"))


def legacy_inputs() -> dict[str, bytes]:
    return {
        "rules/ai-cn.list": b"DOMAIN,ai-cn.example\n",
        "rules/ai-global.list": b"DOMAIN-SUFFIX,ai-global.example\n",
        "rules/network-test.list": b"DOMAIN,test.example\n",
        "rules/us.list": b"DOMAIN,att.example\n",
        "rules/surge/ai-cn.set": b"ai-cn.example\n",
        "rules/surge/network-test.set": b"test.example\n",
        "rules/surge/us.set": b"att.example\n",
        "rules/surge/ai-process.list": b"PROCESS-NAME,AI.app\n",
        "rules/mihomo/cn-direct-domain.mrs": b"legacy-mrs-fixture",
        "rules/mihomo/cn-direct-domain.txt": b"+.cn-direct.example\n",
        "rules/surge/cn-direct.set": b".cn-direct.example\n",
        "rules/mihomo/cn-direct-special.list": b"DOMAIN-KEYWORD,special\n",
        "rules/surge/cn-direct-special.list": b"DOMAIN-KEYWORD,special\n",
        "rules/mihomo/cn-direct-process.list": b"PROCESS-NAME,cn-helper\n",
        "rules/surge/cn-direct-platform.list": b"PROCESS-NAME,cn-helper\n",
    }


def snapshots() -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for source_id, spec in personal_profile.SOURCE_SPECS.items():
        platform = spec["platform"]
        slug = source_id.replace(".", "-")
        if spec["kind"] == "domainset":
            value = f"{slug}.example"
            result[source_id] = (f"+.{value}\n" if platform == "mihomo" else f".{value}\n").encode()
        elif spec["kind"] == "ip":
            result[source_id] = (
                b"IP-CIDR,192.0.2.0/24,no-resolve\n"
                b"DOMAIN,7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe\n"
            )
        else:
            result[source_id] = f"DOMAIN-SUFFIX,{slug}.example\n".encode()
    # Deliberate overlap verifies route priority, not only set membership.
    result["mihomo.apple_intelligence"] = b"DOMAIN,api.apple.example\n"
    result["surge.apple_intelligence"] = b"DOMAIN,api.apple.example\n"
    result["mihomo.apple_cn"] = b"DOMAIN,api.apple.example\n"
    result["surge.apple_cn"] = b"DOMAIN,api.apple.example\n"
    canary = b"DOMAIN,7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe\n"
    result["mihomo.telegram_asn"] = b"IP-ASN,AS64500\n" + canary
    result["surge.telegram_asn"] = b"IP-ASN,AS64500\n" + canary
    return result


def compile_candidate(snapshot: dict[str, bytes] | None = None, profile: dict | None = None):
    return personal_profile.compile(
        snapshot or snapshots(),
        legacy_inputs(),
        profile or profile_value(),
        root=ROOT,
        mrs_converter=lambda text: b"MRS-fixture\n" + text,
    )


class SourceParsingTests(unittest.TestCase):
    def test_unknown_rule_type_empty_source_and_error_page_fail_closed(self) -> None:
        for source in (
            b"DOMAIN-REGEX,^example\\.com$\n",
            b"",
            b"<!doctype html><html>upstream unavailable</html>\n",
        ):
            with self.subTest(source=source), self.assertRaises(personal_profile.ProfileError):
                personal_profile.parse_source(source, "mihomo.lan")

    def test_scalar_flags_nested_conditions_and_opaque_url_regex_are_parsed_strictly(self) -> None:
        parsed = personal_profile.parse_source(
            b"DOMAIN-KEYWORD,google,extended-matching\n", "surge.reject"
        )
        self.assertEqual((parsed[0].value, parsed[0].flags), ("google", ("extended-matching",)))
        for malformed in (
            b"DOMAIN-KEYWORD,google,unknown-option\n",
            b"DOMAIN,example.com,unexpected\n",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(personal_profile.ProfileError):
                personal_profile.parse_source(malformed, "surge.reject")
        with self.assertRaisesRegex(personal_profile.ProfileError, "only supported on Surge"):
            personal_profile.parse_source(b"DOMAIN-KEYWORD,google,extended-matching\n", "mihomo.reject")

        wildcard = personal_profile.parse_source(
            b"DOMAIN-WILDCARD,video-thumbnail2.fc2.com\n", "surge.cdn"
        )
        self.assertEqual(wildcard[0].value, "video-thumbnail2.fc2.com")
        self.assertTrue(personal_profile.rule_matches(wildcard[0], domain="video-thumbnail2.fc2.com"))
        suffix = personal_profile.parse_source(
            b"piano_log.kingsoft.jp\nxtl._domainkey.zoom.us\n", "mihomo.download_domains"
        )
        self.assertEqual([rule.value for rule in suffix], ["piano_log.kingsoft.jp", "xtl._domainkey.zoom.us"])

        url_rule = personal_profile.parse_source(
            b"URL-REGEX,^http://example\\.com/a,b$\n", "surge.download"
        )[0]
        self.assertEqual(url_rule.value, "^http://example\\.com/a,b$")
        self.assertTrue(personal_profile.rule_matches(url_rule, url="http://example.com/a,b"))
        compound = personal_profile.parse_source(
            b"AND,((PROTOCOL,UDP), (DOMAIN-SUFFIX,googlevideo.com))\n", "surge.reject_no_drop"
        )[0]
        self.assertTrue(personal_profile.rule_matches(
            compound, domain="r1.googlevideo.com", protocol="UDP"
        ))
        self.assertFalse(personal_profile.rule_matches(
            compound, domain="r1.googlevideo.com", protocol="TCP"
        ))
        with self.assertRaises(personal_profile.ProfileError):
            personal_profile.parse_source(
                b"AND,((PROTOCOL,UDP), (IP-CIDR,192.0.2.0/24))\n", "surge.reject_no_drop"
            )

    def test_ip_sources_preserve_only_the_fixed_sukka_domain_canary(self) -> None:
        canary = "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe"
        parsed = personal_profile.parse_source(
            f"IP-CIDR,192.0.2.0/24,no-resolve\nDOMAIN,{canary}\n".encode(), "mihomo.ai_ip"
        )
        self.assertEqual([(rule.type, rule.value) for rule in parsed], [
            ("IP-CIDR", "192.0.2.0/24"), ("DOMAIN", canary)
        ])
        with self.assertRaises(personal_profile.ProfileError):
            personal_profile.parse_source(b"IP-CIDR,192.0.2.0/24\nDOMAIN,other.example\n", "mihomo.ai_ip")
        mixed = personal_profile.parse_source(
            b"DOMAIN,service.example\nIP-CIDR,192.0.2.0/24\n", "mihomo.apple_services"
        )
        self.assertEqual([rule.type for rule in mixed], ["DOMAIN", "IP-CIDR"])

    def test_domain_suffix_and_wildcard_have_distinct_matching_semantics(self) -> None:
        suffix = personal_profile.Rule("DOMAIN-SUFFIX", "example.com", platform="mihomo")
        exact = personal_profile.Rule("DOMAIN", "example.com", platform="mihomo")
        wildcard = personal_profile.Rule("DOMAIN-WILDCARD", "api-*.example.com", platform="mihomo")
        self.assertTrue(personal_profile.rule_matches(suffix, domain="api.example.com"))
        self.assertFalse(personal_profile.rule_matches(suffix, domain="notexample.com"))
        self.assertFalse(personal_profile.rule_matches(exact, domain="api.example.com"))
        self.assertTrue(personal_profile.rule_matches(wildcard, domain="api-v2.example.com"))

    def test_index_covers_special_domain_ip_process_user_agent_asn_and_geoip_types(self) -> None:
        types = [
            ("DOMAIN-KEYWORD", "needle"), ("DOMAIN-WILDCARD", "api-*.example.com"),
            ("IP-CIDR", "192.0.2.0/24"),
            ("IP-CIDR6", "2001:db8::/32"), ("IP-ASN", "64500"),
            ("PROCESS-NAME-WILDCARD", "Player*"),
            ("GEOIP", "CN"), ("MATCH", "*"),
        ]
        rules = [personal_profile.Rule(typ, value, platform="mihomo") for typ, value in types]
        index = personal_profile.RuleIndex([{"id": "types", "action": "US", "rules": rules}], "mihomo")
        queries = [
            ({"domain": "has-needle.example"}, "DOMAIN-KEYWORD"),
            ({"domain": "api-v2.example.com"}, "DOMAIN-WILDCARD"),
            ({"ip": "192.0.2.7"}, "IP-CIDR"),
            ({"ip": "2001:db8::7"}, "IP-CIDR6"),
            ({"asn": "AS64500"}, "IP-ASN"),
            ({"process": "Player.exe"}, "PROCESS-NAME-WILDCARD"),
            ({"geoip": "CN"}, "GEOIP"),
        ]
        for query, expected_type in queries:
            with self.subTest(expected_type=expected_type):
                self.assertEqual(index.first_match(**query).rule.type, expected_type)

    def test_surge_user_agent_and_platform_process_semantics(self) -> None:
        surge_stages = [{
            "id": "surge-process", "action": "DIRECT", "rules": [
                personal_profile.Rule("USER-AGENT", "TeslaMap", platform="surge"),
                personal_profile.Rule("USER-AGENT", "NeteaseMusic*", platform="surge"),
                personal_profile.Rule("PROCESS-NAME", "qbittorrent*", platform="surge"),
                personal_profile.Rule("PROCESS-NAME", "WeChat", platform="surge"),
                personal_profile.Rule("PROCESS-NAME", "/Applications/ChatGPT.app/", platform="surge"),
            ],
        }]
        surge = personal_profile.RuleIndex(surge_stages, "surge")
        self.assertIsNone(surge.first_match(user_agent="XTeslaMapX"))
        self.assertEqual(surge.first_match(user_agent="TeslaMap").rule.value, "TeslaMap")
        self.assertEqual(surge.first_match(user_agent="NeteaseMusic/1.2").rule.value, "NeteaseMusic*")
        self.assertIsNone(surge.first_match(user_agent="NeteaseMusi"))
        self.assertEqual(surge.first_match(process="qbittorrent-nox").rule.value, "qbittorrent*")
        wechat_path = "/Applications/WeChat.app/Contents/MacOS/WeChat"
        self.assertEqual(surge.first_match(process="WeChat").rule.value, "WeChat")
        self.assertEqual(surge.first_match(process=wechat_path).rule.value, "WeChat")
        self.assertIsNone(surge.first_match(process="/Applications/WeChat.app/Contents/MacOS/wechat"))
        self.assertTrue(personal_profile.rule_matches(
            personal_profile.Rule("PROCESS-NAME", "WeChat", platform="surge"), process=wechat_path
        ))
        self.assertFalse(personal_profile.rule_matches(
            personal_profile.Rule("PROCESS-NAME", "WeChat", platform="surge"), process="wechat"
        ))
        self.assertEqual(
            surge.first_match(process="/Applications/ChatGPT.app/Contents/MacOS/ChatGPT").rule.value,
            "/Applications/ChatGPT.app/",
        )
        self.assertIsNone(surge.first_match(process="/Applications/ChatGPT.app2/Contents/MacOS/ChatGPT"))

        mihomo_stages = [{
            "id": "mihomo-process", "action": "DIRECT", "rules": [
                personal_profile.Rule("PROCESS-NAME", "qbittorrent*", platform="mihomo"),
            ],
        }]
        mihomo = personal_profile.RuleIndex(mihomo_stages, "mihomo")
        self.assertIsNone(mihomo.first_match(process="qbittorrent-nox"))
        self.assertEqual(mihomo.first_match(process="QBITTORRENT*").rule.value, "qbittorrent*")

    def test_rule_index_reports_semantics_it_does_not_model(self) -> None:
        index = personal_profile.RuleIndex([{
            "id": "limited", "action": "US", "extended_matching": True,
            "rules": [personal_profile.Rule("IP-CIDR", "192.0.2.0/24", ("no-resolve",), platform="surge")],
        }], "surge")
        self.assertEqual({item["type"] for item in index.comparison_limitations}, {
            "extended-matching", "no-resolve"
        })

    def test_unsupported_profile_source_is_rejected(self) -> None:
        profile = profile_value()
        profile["stages"][0]["sources"][0] = "manual:unimplemented"
        with self.assertRaises(personal_profile.ProfileError):
            personal_profile.validate_profile(profile)

    def test_terminal_rules_are_restricted_to_their_matching_manual_stages(self) -> None:
        ordinary_terminal = profile_value()
        ordinary_terminal["stages"][0]["rule"] = {"type": "MATCH", "value": "*", "flags": []}
        with self.assertRaisesRegex(personal_profile.ProfileError, "only manual:geoip-cn"):
            personal_profile.validate_profile(ordinary_terminal)

        mixed_terminal_source = profile_value()
        geoip = next(stage for stage in mixed_terminal_source["stages"] if stage["id"] == "geoip-cn")
        geoip["sources"].append("mihomo.lan")
        with self.assertRaisesRegex(personal_profile.ProfileError, "sole stage source"):
            personal_profile.validate_profile(mixed_terminal_source)

        mismatched_terminal = profile_value()
        geoip = next(stage for stage in mismatched_terminal["stages"] if stage["id"] == "geoip-cn")
        geoip["sources"] = ["manual:default"]
        with self.assertRaisesRegex(personal_profile.ProfileError, "source, rule, and action"):
            personal_profile.validate_profile(mismatched_terminal)

    def test_manual_jp_members_reject_rule_injection_fields(self) -> None:
        for injected in ("jp.example,IP-CIDR,0.0.0.0/0", "jp.example\nMATCH,*"):
            profile = profile_value()
            profile["jp_members"] = [{
                "type": "DOMAIN", "value": injected, "source": "review", "reason": "verified",
            }]
            with self.subTest(value=injected), self.assertRaises(personal_profile.ProfileError):
                personal_profile.validate_profile(profile)


class CompilationAndMatchingTests(unittest.TestCase):
    def test_surge_preserves_dns_lookup_boundary_between_process_and_lan_ip_sets(self):
        source = snapshots()
        for platform in ("mihomo", "surge"):
            source[f"{platform}.lan_ip"] = b"IP-CIDR,192.168.0.0/16\n"
        candidate = compile_candidate(source)
        groups = {stage["id"]: stage["group_by_platform"] for stage in candidate.stages}
        self.assertNotEqual(groups["cn-direct-process"]["surge"], groups["lan-ip"]["surge"])
        self.assertEqual(groups["cn-direct-process"]["mihomo"], groups["lan-ip"]["mihomo"])
        self.assertNotIn(b"IP-CIDR", candidate.files["rules/personal/surge/cn-direct-process.list"])
        self.assertEqual(candidate.files["rules/personal/surge/lan-ip.list"], b"IP-CIDR,192.168.0.0/16\n")

    def test_stage_priority_terminal_rules_and_domain_only_dns(self) -> None:
        candidate = compile_candidate()
        index = personal_profile.RuleIndex(candidate.stages, "mihomo")
        apple = index.first_match(domain="api.apple.example")
        self.assertIsNotNone(apple)
        self.assertEqual((apple.stage["id"], apple.action, apple.dns), ("apple-intelligence", "US", "foreign"))
        china = index.first_match(ip="203.0.113.7", geoip="CN")
        self.assertIsNotNone(china)
        self.assertEqual((china.stage["id"], china.action, china.rule.type), ("geoip-cn", "DIRECT", "GEOIP"))
        default = index.first_match(domain="unmatched.example")
        self.assertIsNotNone(default)
        self.assertEqual((default.stage["id"], default.action, default.rule.type), ("default-us", "US", "MATCH"))
        ipv4 = index.first_match(ip="192.0.2.7")
        self.assertEqual((ipv4.stage["id"], ipv4.action, ipv4.rule.type, ipv4.rule.flags),
                         ("lan-ip", "DIRECT", "IP-CIDR", ("no-resolve",)))
        ipv6 = personal_profile.RuleIndex(
            [{"id": "v6", "action": "DIRECT", "rules": [personal_profile.Rule(
                "IP-CIDR6", "2001:db8::/32", platform="mihomo"
            )]}], "mihomo"
        ).first_match(ip="2001:db8::7")
        self.assertIsNotNone(ipv6)
        self.assertEqual(ipv6.rule.type, "IP-CIDR6")
        asn = index.first_match(asn="AS64500")
        self.assertEqual((asn.stage["id"], asn.action, asn.rule.type), ("telegram-ip", "US", "IP-ASN"))
        self.assertFalse(any(
            group["id"] in {"geoip-cn", "default-us"}
            for platform_groups in candidate.manifest["groups"].values()
            for group in platform_groups
        ))

    def test_terminal_stage_is_a_route_group_merge_barrier(self) -> None:
        profile = profile_value()
        geoip = next(stage for stage in profile["stages"] if stage["id"] == "geoip-cn")
        profile["stages"].remove(geoip)
        telegram_index = next(i for i, stage in enumerate(profile["stages"]) if stage["id"] == "telegram-ip")
        profile["stages"].insert(telegram_index, geoip)
        candidate = compile_candidate(profile=profile)
        stages = {stage["id"]: stage for stage in candidate.stages}
        self.assertNotEqual(
            stages["ai-ip"]["group_by_platform"]["mihomo"],
            stages["telegram-ip"]["group_by_platform"]["mihomo"],
        )
        interface = personal_profile._client_interface(candidate.manifest)["mihomo"]
        ids = [(entry["entry"], entry.get("id") or entry.get("stage_id")) for entry in interface]
        ai_position = ids.index(("group", stages["ai-ip"]["group_by_platform"]["mihomo"]))
        geoip_position = ids.index(("terminal", "geoip-cn"))
        telegram_position = ids.index(("group", stages["telegram-ip"]["group_by_platform"]["mihomo"]))
        self.assertLess(ai_position, geoip_position)
        self.assertLess(geoip_position, telegram_position)

    def test_empty_jp_route_and_dns_selector_are_real_and_stable(self) -> None:
        empty = compile_candidate()
        mihomo = next(group for group in empty.manifest["groups"]["mihomo"] if group["id"] == "jp-manual")
        surge = next(group for group in empty.manifest["groups"]["surge"] if group["id"] == "jp-manual")
        self.assertEqual(mihomo["rule_count"], 0)
        self.assertEqual(surge["rule_count"], 0)
        self.assertEqual((mihomo["path"], mihomo["dns_path"]), (
            "rules/personal/mihomo/jp-manual.list", "rules/personal/mihomo/dns-jp-manual.list"
        ))
        self.assertEqual((surge["path"], surge["dns_path"]), (
            "rules/personal/surge/jp-manual.list", "rules/personal/surge/dns-jp-manual.list"
        ))
        self.assertTrue(empty.files[mihomo["path"]].startswith(b"#"))
        self.assertTrue(empty.files[mihomo["dns_path"]].startswith(b"#"))

        with_member = profile_value()
        with_member["jp_members"] = [
            {"type": "DOMAIN-SUFFIX", "value": "jp.example", "source": "manual review",
             "reason": "verified JP service host"},
            {"type": "IP-CIDR", "value": "198.51.100.0/24", "source": "manual review",
             "reason": "verified JP service network"},
        ]
        populated = compile_candidate(profile=with_member)
        jp = personal_profile.RuleIndex(populated.stages, "mihomo").first_match(domain="api.jp.example")
        self.assertEqual((jp.stage["id"], jp.action, jp.dns), ("jp-manual", "JP", "jp"))
        populated_jp = next(group for group in populated.manifest["groups"]["mihomo"] if group["id"] == "jp-manual")
        self.assertEqual(populated_jp["path"], mihomo["path"])
        self.assertEqual(populated_jp["dns_path"], mihomo["dns_path"])
        self.assertIn(b"DOMAIN-SUFFIX,jp.example", populated.files[mihomo["dns_path"]])
        self.assertNotIn(b"IP-CIDR", populated.files[mihomo["dns_path"]])

    def test_cn_direct_special_matching_flag_preserves_existing_rule_behavior(self) -> None:
        special = next(stage for stage in profile_value()["stages"] if stage["id"] == "cn-direct-special")
        self.assertFalse(special["extended_matching"])

    def test_per_rule_extended_matching_becomes_a_stable_group_flag_or_fails(self) -> None:
        snapshot = snapshots()
        snapshot["surge.lan"] = b"DOMAIN-KEYWORD,lan,extended-matching\n"
        candidate = compile_candidate(snapshot)
        surge_group = next(group for group in candidate.manifest["groups"]["surge"] if group["id"] == "infra-lan")
        mihomo_group = next(group for group in candidate.manifest["groups"]["mihomo"] if group["id"] == "infra-lan")
        self.assertTrue(surge_group["extended_matching"])
        self.assertFalse(mihomo_group["extended_matching"])
        self.assertNotIn(b"extended-matching", candidate.files[surge_group["path"]])

        snapshot["surge.lan"] = b"DOMAIN,one.lan\nDOMAIN-KEYWORD,two,extended-matching\n"
        with self.assertRaisesRegex(personal_profile.ProfileError, "mixes per-rule extended-matching"):
            compile_candidate(snapshot)

    def test_hashes_are_deterministic_and_change_with_inputs(self) -> None:
        first = compile_candidate()
        replayed = compile_candidate()
        self.assertEqual(first.files, replayed.files)
        changed_snapshot = snapshots()
        changed_snapshot["mihomo.cdn_domains"] += b"+.new-cdn.example\n"
        changed = compile_candidate(changed_snapshot)
        self.assertNotEqual(first.manifest["sources"]["mihomo.cdn_domains"]["sha256"],
                            changed.manifest["sources"]["mihomo.cdn_domains"]["sha256"])
        self.assertNotEqual(first.manifest["groups"]["mihomo"], changed.manifest["groups"]["mihomo"])
        self.assertNotEqual(first.manifest["profile"]["sha256"], compile_candidate(profile={
            **profile_value(), "jp_members": [{
                "type": "DOMAIN", "value": "one.jp.example", "source": "manual review", "reason": "verified"
            }]
        }).manifest["profile"]["sha256"])

    def test_output_contract_gate_blocks_format_action_and_merge_changes(self) -> None:
        original = compile_candidate()
        pure_domain_to_special = snapshots()
        pure_domain_to_special["mihomo.lan"] = b"DOMAIN-WILDCARD,*.lan.example\n"
        changed_format = compile_candidate(pure_domain_to_special)
        with self.assertRaisesRegex(personal_profile.ProfileError, "interface changed"):
            personal_profile._require_stable_client_interface(original.manifest, changed_format.manifest)

        changed_action = copy.deepcopy(original.manifest)
        changed_action["groups"]["surge"][0]["action"] = "REJECT"
        with self.assertRaisesRegex(personal_profile.ProfileError, "interface changed"):
            personal_profile._require_stable_client_interface(original.manifest, changed_action)
        personal_profile._require_stable_client_interface(original.manifest, changed_action, accept_change=True)

        changed_profile = profile_value()
        next(stage for stage in changed_profile["stages"] if stage["id"] == "att-us")["action"] = "TEST"
        changed_merge = compile_candidate(profile=changed_profile)
        with self.assertRaisesRegex(personal_profile.ProfileError, "interface changed"):
            personal_profile._require_stable_client_interface(original.manifest, changed_merge.manifest)

        moved_terminal = copy.deepcopy(original.manifest)
        geoip_index = next(i for i, stage in enumerate(moved_terminal["stages"]) if stage["id"] == "geoip-cn")
        default_index = next(i for i, stage in enumerate(moved_terminal["stages"]) if stage["id"] == "default-us")
        moved_terminal["stages"][geoip_index], moved_terminal["stages"][default_index] = (
            moved_terminal["stages"][default_index], moved_terminal["stages"][geoip_index]
        )
        with self.assertRaisesRegex(personal_profile.ProfileError, "interface changed"):
            personal_profile._require_stable_client_interface(original.manifest, moved_terminal)
        changed_terminal = copy.deepcopy(original.manifest)
        terminal = next(stage for stage in changed_terminal["stages"] if stage["id"] == "geoip-cn")
        terminal["terminal_rule"]["flags"] = []
        with self.assertRaisesRegex(personal_profile.ProfileError, "interface changed"):
            personal_profile._require_stable_client_interface(original.manifest, changed_terminal)

    def test_offline_bundle_tamper_is_detected(self) -> None:
        candidate = compile_candidate()
        with tempfile.TemporaryDirectory(prefix="personal-profile-test-") as directory:
            root = Path(directory)
            (root / personal_profile.PROFILE_PATH).parent.mkdir(parents=True, exist_ok=True)
            (root / personal_profile.PROFILE_PATH).write_text(json.dumps(profile_value()), encoding="utf-8")
            for relative, content in legacy_inputs().items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            personal_profile.write_bundle_transactionally(root, candidate.files)
            with mock.patch.object(personal_profile, "_convert_mrs", side_effect=lambda data, *_args: b"MRS-fixture\n" + data):
                personal_profile.validate_bundle(root)
                (root / "rules/personal/mihomo/dns-jp-manual.list").write_bytes(b"tampered\n")
                with self.assertRaisesRegex(personal_profile.ProfileError, "replay differs"):
                    personal_profile.validate_bundle(root)

    def test_update_honors_publish_hold_and_rejects_nonobject_prior_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="personal-profile-hold-") as directory:
            root = Path(directory)
            root.mkdir(parents=True, exist_ok=True)
            (root / "policy.json").write_text(json.dumps({
                "publish_hold": {"enabled": True, "reason": "rollback review"}
            }), encoding="utf-8")
            with self.assertRaisesRegex(personal_profile.ProfileError, "publish_hold"):
                personal_profile.update(root, offline=True)
            self.assertFalse((root / personal_profile.MANIFEST_PATH).exists())

        with tempfile.TemporaryDirectory(prefix="personal-profile-bad-manifest-") as directory:
            root = Path(directory)
            (root / "policy.json").write_text(json.dumps({
                "publish_hold": {"enabled": False, "reason": ""}
            }), encoding="utf-8")
            profile_path = root / personal_profile.PROFILE_PATH
            profile_path.parent.mkdir(parents=True, exist_ok=True)
            profile_path.write_text(json.dumps(profile_value()), encoding="utf-8")
            for source_id, spec in personal_profile.SOURCE_SPECS.items():
                target = root / spec["archive_path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(snapshots()[source_id])
            for relative, content in legacy_inputs().items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            manifest_path = root / personal_profile.MANIFEST_PATH
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(personal_profile.ProfileError, "JSON object"):
                personal_profile.update(root, offline=True)


if __name__ == "__main__":
    unittest.main()
