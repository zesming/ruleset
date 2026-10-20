from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import personal_profile  # noqa: E402
from test_personal_profile import compile_candidate, legacy_inputs, old_compact_group_id, profile_value, snapshots  # noqa: E402


CANARY = b"7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe"
EXPECTED_COMPACT_RENAMES = {
    "priority-lan-domain": "lan-direct",
    "priority-test-domain": "test",
    "priority-reject-classical": "reject-drop",
    "priority-reject-domain": "reject",
    "priority-reject-classical-2": "reject-rules",
    "priority-reject-domain-2": "reject-extra",
    "priority-reject-classical-3": "reject-no-drop",
    "priority-reject-classical-4": "reject-extra-rules",
    "priority-jp-classical": "jp-proxy",
    "priority-us-classical": "us-proxy",
    "priority-us-classical-2": "us-proxy-ext",
    "priority-cn-direct-domain": "cn-direct",
    "priority-cn-direct-classical": "cn-direct-extra",
    "priority-lan-ip-classical": "lan-direct-ip",
    "priority-reject-ip-classical": "reject-ip",
    "priority-jp-ip-classical": "jp-proxy-ip",
    "priority-us-ip-classical": "us-proxy-ip",
    "priority-direct-ip-classical": "direct-ip",
    "priority-us-ip-late-classical": "us-proxy-ip-late",
    "priority-cn-ip-classical": "cn-direct-ip",
}


def compact_groups(candidate, platform: str) -> list[dict]:
    return candidate.manifest["compact"]["groups"][platform]


def slot_groups(candidate, platform: str, slot: str) -> list[dict]:
    return [group for group in compact_groups(candidate, platform) if group["slot"] == slot]


def old_compact_id(group: dict, ordinals: dict[tuple[str, str], int]) -> str:
    slot, capability = group["slot"], group["capability"]
    key = (slot, capability)
    ordinals[key] = ordinals.get(key, 0) + 1
    group_id = f"priority-{slot}-{capability}"
    return group_id if ordinals[key] == 1 else f"{group_id}-{ordinals[key]}"


class PriorityProfileTests(unittest.TestCase):
    def test_compact_stages_follow_priority_order_and_keep_terminals_last(self) -> None:
        candidate = compile_candidate()
        expected = [
            "lan", "test", "reject", "jp", "us", "cn-direct",
            "lan-ip", "reject-ip", "jp-ip", "us-ip", "direct-ip", "us-ip-late", "cn-ip",
        ]

        for platform in ("mihomo", "surge"):
            stages = candidate.compact_stages[platform]
            groups = compact_groups(candidate, platform)
            slots = [stage["slot"] for stage in stages if stage.get("slot") is not None]
            first_positions = {slot: slots.index(slot) for slot in expected}
            self.assertEqual(
                [first_positions[slot] for slot in expected],
                sorted(first_positions.values()),
            )
            self.assertEqual([stage["id"] for stage in stages[-2:]], ["geoip-cn", "default-us"])
            self.assertEqual([group["id"] for group in groups], [
                stage["group_by_platform"][platform]
                for stage in stages if stage["group_by_platform"].get(platform) is not None
            ])
            for group in groups:
                self.assertFalse(group["id"].startswith("priority-"))
                self.assertEqual(Path(group["path"]).stem, group["id"])
                self.assertEqual(Path(group["path"]).parent.name, "route")
                self.assertEqual(group["dns_path"], group["path"])
                self.assertEqual(group["dns_kind"], "route")
                self.assertEqual(group["kind"], "route")

    def test_canonical_names_replace_old_paths_and_manifest_closes_outputs(self) -> None:
        candidate = compile_candidate()
        self.assertEqual(personal_profile.LEGACY_COMPACT_GROUP_IDS, EXPECTED_COMPACT_RENAMES)
        canonical_paths: list[str] = []

        for platform in ("mihomo", "surge"):
            groups = compact_groups(candidate, platform)
            group_ids = [group["id"] for group in groups]
            paths = [group["path"] for group in groups]
            self.assertEqual(len(group_ids), len(set(group_ids)))
            self.assertEqual(len(paths), len(set(paths)))
            canonical_paths.extend(paths)
            ordinals: dict[tuple[str, str], int] = {}
            for group in groups:
                old_id = old_compact_group_id(group, ordinals)
                if old_id in EXPECTED_COMPACT_RENAMES:
                    self.assertEqual(group["id"], EXPECTED_COMPACT_RENAMES[old_id])
                self.assertNotIn("priority-", group["id"])
                self.assertNotIn("classical", group["id"])
                self.assertNotIn("domain", group["id"])
                self.assertEqual(group["path"].split("/")[-2], "route")
                self.assertIn(group["path"], candidate.manifest["outputs"])
                old_path = f"rules/personal/{platform}/{old_id}{Path(group['path']).suffix}"
                self.assertNotIn(old_path, candidate.files)
                self.assertNotIn(old_path, candidate.manifest["outputs"])
            referenced_ids = {
                stage["group_by_platform"][platform]
                for stage in candidate.manifest["compact"]["stages"][platform]
                if stage["group_by_platform"].get(platform) is not None
            }
            self.assertEqual(referenced_ids, set(group_ids))

        self.assertTrue(canonical_paths)
        self.assertEqual(len(canonical_paths), len(set(canonical_paths)))
        for path, metadata in candidate.manifest["outputs"].items():
            self.assertIn(path, candidate.files)
            self.assertEqual(metadata["bytes"], len(candidate.files[path]))
            self.assertEqual(metadata["sha256"], personal_profile.sha256(candidate.files[path]))

    def test_arbitrary_fixture_slot_names_are_generic_unique_and_capabilities_fail_closed(self) -> None:
        snapshot = snapshots()
        snapshot["mihomo.lan"] = (
            "".join(f"DOMAIN-SUFFIX,fixture-{number}.example\n" for number in range(1001))
            + "DOMAIN-KEYWORD,fixture-keyword\n"
        ).encode()
        profile = profile_value()
        next(slot for slot in profile["compact"]["slots"] if slot["id"] == "lan")["id"] = "fixture-lan"
        candidate = compile_candidate(snapshot, profile)
        fixture_groups = slot_groups(candidate, "mihomo", "fixture-lan")
        self.assertEqual([group["id"] for group in fixture_groups], [
            "fixture-lan-direct", "fixture-lan-direct-extra",
        ])
        self.assertTrue(all("priority-" not in group["id"] for group in fixture_groups))
        self.assertTrue(set(group["id"] for group in fixture_groups).isdisjoint(EXPECTED_COMPACT_RENAMES.values()))
        self.assertEqual(len({group["path"] for group in fixture_groups}), len(fixture_groups))
        self.assertEqual(
            personal_profile._compact_group_name("fixture-reject", "REJECT", "classical", 1),
            ("fixture-reject", False),
        )
        self.assertEqual(
            personal_profile._compact_group_name("fixture-test", "TEST", "domain", 1),
            ("fixture-test", False),
        )
        with self.assertRaisesRegex(personal_profile.ProfileError, "unsupported compact group capability"):
            personal_profile._compact_group_name("fixture-lan", "DIRECT", "unknown", 1)

    def test_legacy_name_migration_still_requires_interface_acceptance(self) -> None:
        candidate = compile_candidate()
        legacy = copy.deepcopy(candidate.manifest)
        old_id_by_new: dict[str, dict[str, str]] = {"mihomo": {}, "surge": {}}

        for platform in ("mihomo", "surge"):
            ordinals: dict[tuple[str, str], int] = {}
            for group in legacy["compact"]["groups"][platform]:
                new_id = group["id"]
                old_id = old_compact_id(group, ordinals)
                old_path = f"rules/personal/{platform}/{old_id}{Path(group['path']).suffix}"
                old_id_by_new[platform][new_id] = old_id
                group["id"] = old_id
                group["path"] = old_path
                group["dns_path"] = old_path
            for stage in legacy["compact"]["stages"][platform]:
                old_id = old_id_by_new[platform].get(stage["id"])
                if old_id is not None:
                    stage["id"] = old_id
                group_id = stage["group_by_platform"].get(platform)
                if group_id in old_id_by_new[platform]:
                    stage["group_by_platform"][platform] = old_id_by_new[platform][group_id]

        with self.assertRaisesRegex(personal_profile.ProfileError, "client resource interface changed"):
            personal_profile._require_stable_client_interface(legacy, candidate.manifest)
        personal_profile._require_stable_client_interface(
            legacy, candidate.manifest, accept_change=True,
        )

    def test_early_direct_test_and_canary_handling_preserve_fine_interface(self) -> None:
        candidate = compile_candidate()

        for platform in ("mihomo", "surge"):
            lan = slot_groups(candidate, platform, "lan")
            test = slot_groups(candidate, platform, "test")
            self.assertEqual(len(lan), 1)
            self.assertEqual(lan[0]["action"], "DIRECT")
            self.assertEqual(lan[0]["dns"], "system")
            self.assertEqual(len(test), 1)
            self.assertEqual(test[0]["action"], "TEST")
            self.assertEqual(test[0]["dns"], "test")
            self.assertEqual(candidate.manifest["stages"][2]["dns"], "foreign")
            compact_text = b"".join(
                candidate.files[group["path"]]
                for group in compact_groups(candidate, platform)
            )
            self.assertNotIn(CANARY, compact_text)

            fine_ip = next(
                group for group in candidate.manifest["groups"][platform]
                if "telegram-ip" in group["stages"]
            )
            self.assertIn(CANARY, candidate.files[fine_ip["path"]])

        self.assertEqual(len(personal_profile.LEGACY_INPUT_PATHS), 15)

    def test_compatible_direct_and_us_sources_are_collected_by_slot(self) -> None:
        snapshot = snapshots()
        for platform in ("mihomo", "surge"):
            prefix = "+." if platform == "mihomo" else "."
            snapshot[f"{platform}.game_download"] = "".join(
                f"{prefix}download-{number}.example\n" for number in range(1100)
            ).encode()
        candidate = compile_candidate(snapshot)

        for platform in ("mihomo", "surge"):
            direct_domains = slot_groups(candidate, platform, "cn-direct")
            domain_group = next(group for group in direct_domains if group["capability"] == "domain")
            complex_group = next(group for group in direct_domains if group["capability"] == "classical")
            expected_extension = ".mrs" if platform == "mihomo" else ".set"
            self.assertTrue(domain_group["path"].endswith(expected_extension))
            domain_data = candidate.files[domain_group["path"]]
            if platform == "mihomo":
                self.assertTrue(domain_data.startswith(b"MRS-fixture\n"))
            else:
                domain_lines = domain_data.decode().splitlines()
                self.assertTrue(domain_lines)
                self.assertTrue(all("," not in line for line in domain_lines))
            self.assertIn("cn-direct-process", complex_group["stages"])
            self.assertIn("cn-direct-special", complex_group["stages"])
            self.assertEqual(domain_group["dns_path"], domain_group["path"])
            self.assertEqual(complex_group["dns_path"], complex_group["path"])

            us_groups = slot_groups(candidate, platform, "us")
            self.assertTrue(all(group["format"] == "text" for group in us_groups))
            if platform == "mihomo":
                self.assertEqual(len(us_groups), 1)
                self.assertEqual(us_groups[0]["stages"], [
                    "att-us", "ai-global", "apple-intelligence", "cdn", "telegram",
                ])
            else:
                self.assertEqual([group["extended_matching"] for group in us_groups], [False, True])
                self.assertEqual(us_groups[0]["stages"], ["att-us", "ai-global", "ai-process", "cdn", "telegram"])
                self.assertEqual(us_groups[1]["stages"], ["apple-intelligence"])

    def test_reject_and_us_priority_precede_broad_cn_direct_overlap(self) -> None:
        snapshot = snapshots()
        snapshot["mihomo.reject"] += b"DOMAIN-SUFFIX,service.example\n"
        snapshot["surge.reject"] += b"DOMAIN-SUFFIX,service.example\n"
        legacy = legacy_inputs()
        legacy["rules/mihomo/cn-direct-domain.txt"] += b"+.service.example\n+.us-service.example\n"
        legacy["rules/surge/cn-direct.set"] += b".service.example\n.us-service.example\n"
        legacy["rules/us.list"] += b"DOMAIN-SUFFIX,us-service.example\n"
        legacy["rules/surge/us.set"] += b".us-service.example\n"
        candidate = personal_profile.compile(
            snapshot, legacy, profile_value(), root=ROOT,
            mrs_converter=lambda text: b"MRS-fixture\n" + text,
        )

        for platform in ("mihomo", "surge"):
            index = personal_profile.RuleIndex(candidate.compact_stages[platform], platform)
            rejected = index.first_match(domain="ad.service.example")
            self.assertIsNotNone(rejected)
            self.assertEqual(rejected.action, "REJECT")
            us_match = index.first_match(domain="ad.us-service.example")
            self.assertIsNotNone(us_match)
            self.assertEqual(us_match.action, "US")
            ordered_slots = [stage.get("slot") for stage in candidate.compact_stages[platform] if stage.get("slot")]
            self.assertLess(ordered_slots.index("us"), ordered_slots.index("cn-direct"))

    def test_reject_modes_and_surge_extended_matching_keep_source_subrun_order(self) -> None:
        candidate = compile_candidate()
        mihomo_rejects = slot_groups(candidate, "mihomo", "reject")
        surge_rejects = slot_groups(candidate, "surge", "reject")

        self.assertEqual([group["reject_mode"] for group in mihomo_rejects], ["drop", "plain", "no-drop", "plain"])
        self.assertTrue(all(group["extended_matching"] is False for group in mihomo_rejects))
        self.assertEqual(
            [group["reject_mode"] for group in surge_rejects],
            ["drop", "plain", "plain", "no-drop", "plain"],
        )
        self.assertEqual(
            [group["extended_matching"] for group in surge_rejects],
            [False, True, False, True, False],
        )
        self.assertIn("reject-rules", surge_rejects[1]["stages"])

    def test_non_resolving_ip_rules_stay_in_their_original_priority_slots(self) -> None:
        snapshot = snapshots()
        snapshot["mihomo.reject"] += b"IP-CIDR,192.0.2.0/24,no-resolve\n"
        snapshot["surge.reject"] += b"IP-CIDR,192.0.2.0/24,no-resolve\n"
        snapshot["mihomo.apple_services"] += b"IP-CIDR6,2001:db8::/32,no-resolve\n"
        snapshot["surge.apple_services"] += b"IP-CIDR6,2001:db8::/32,no-resolve\n"
        candidate = compile_candidate(snapshot)

        for platform in ("mihomo", "surge"):
            reject_classical = next(
                group for group in slot_groups(candidate, platform, "reject")
                if group["capability"] == "classical" and "reject-rules" in group["stages"]
            )
            direct_classical = next(
                group for group in slot_groups(candidate, platform, "cn-direct")
                if group["capability"] == "classical"
            )
            self.assertIn(b"IP-CIDR,192.0.2.0/24,no-resolve", candidate.files[reject_classical["path"]])
            self.assertIn(b"IP-CIDR6,2001:db8::/32,no-resolve", candidate.files[direct_classical["path"]])
            self.assertEqual(slot_groups(candidate, platform, "reject-ip")[0]["stages"], ["reject-ip"])

    def test_small_mixed_run_uses_one_classical_resource_but_large_run_stays_split(self) -> None:
        small_snapshot = snapshots()
        small_snapshot["mihomo.lan"] = b"DOMAIN-SUFFIX,lan.example\nDOMAIN-KEYWORD,lan\n"
        small = compile_candidate(small_snapshot)
        small_lan = slot_groups(small, "mihomo", "lan")
        self.assertEqual(len(small_lan), 1)
        self.assertEqual(small_lan[0]["capability"], "classical")
        self.assertIn(b"DOMAIN-SUFFIX,lan.example", small.files[small_lan[0]["path"]])
        self.assertIn(b"DOMAIN-KEYWORD,lan", small.files[small_lan[0]["path"]])

        large_snapshot = snapshots()
        large_snapshot["mihomo.reject"] += "".join(
            f"DOMAIN-SUFFIX,blocked-{index}.large.example\n" for index in range(1000)
        ).encode()
        large_snapshot["mihomo.reject"] += b"DOMAIN-KEYWORD,large-block-list\n"
        large = compile_candidate(large_snapshot)
        large_reject = [
            group for group in slot_groups(large, "mihomo", "reject")
            if "reject-rules" in group["stages"]
        ]
        self.assertEqual(len(large_reject), 2)
        self.assertEqual({group["capability"] for group in large_reject}, {"domain", "classical"})
        self.assertTrue(any(group["path"].endswith(".mrs") for group in large_reject))
        self.assertTrue(any(group["path"].endswith(".list") for group in large_reject))
        classical = next(group for group in large_reject if group["capability"] == "classical")
        self.assertIn(b"DOMAIN-KEYWORD,large-block-list", large.files[classical["path"]])

    def test_post_ip_slots_coalesce_by_priority_and_keep_empty_jp_ip_interface(self) -> None:
        candidate = compile_candidate()
        expected = {
            "lan-ip": ["lan-ip"],
            "reject-ip": ["reject-ip"],
            "jp-ip": [],
            "direct-ip": ["apple-ip", "download-ip"],
            "us-ip-late": ["cdn-ip"],
            "cn-ip": ["domestic-ip"],
        }

        for platform in ("mihomo", "surge"):
            us_expected = [["ai-ip", "telegram-ip"]] if platform == "mihomo" else [["ai-ip"], ["telegram-ip"]]
            expected_stages = {
                **expected,
                "us-ip": [stage for bucket in us_expected for stage in bucket],
            }
            expected_slots = ["lan-ip", "reject-ip", "jp-ip", *("us-ip" for _ in us_expected),
                              "direct-ip", "us-ip-late", "cn-ip"]
            ip_groups = [group for group in compact_groups(candidate, platform) if group["slot"] in expected_stages]
            self.assertEqual([group["slot"] for group in ip_groups], expected_slots)
            observed_us_groups = [group for group in ip_groups if group["slot"] == "us-ip"]
            self.assertEqual([group["stages"] for group in observed_us_groups], us_expected)
            for group in ip_groups:
                if group["slot"] != "us-ip":
                    self.assertEqual(group["stages"], expected_stages[group["slot"]])
                self.assertEqual(group["dns"], "none")
                self.assertFalse(group["extended_matching"])
                self.assertEqual(group["dns_path"], group["path"])

    def test_jp_route_and_ip_paths_are_stable_when_future_members_are_added(self) -> None:
        empty = compile_candidate()
        future_profile = profile_value()
        future_profile["jp_members"] = [
            {"type": "DOMAIN-SUFFIX", "value": "jp.example", "source": "review", "reason": "verified domain"},
            {"type": "IP-CIDR", "value": "198.51.100.0/24", "source": "review", "reason": "verified network"},
        ]
        populated = compile_candidate(profile=future_profile)

        for platform in ("mihomo", "surge"):
            empty_jp = slot_groups(empty, platform, "jp")[0]
            populated_jp = slot_groups(populated, platform, "jp")[0]
            empty_jp_ip = slot_groups(empty, platform, "jp-ip")[0]
            populated_jp_ip = slot_groups(populated, platform, "jp-ip")[0]
            self.assertEqual(empty_jp["path"], populated_jp["path"])
            self.assertEqual(Path(empty_jp["path"]).stem, "jp-proxy")
            self.assertEqual(empty_jp["dns_path"], empty_jp["path"])
            self.assertEqual(populated_jp["dns_path"], populated_jp["path"])
            self.assertEqual(empty_jp_ip["path"], populated_jp_ip["path"])
            self.assertEqual(Path(empty_jp_ip["path"]).stem, "jp-proxy-ip")
            self.assertEqual(populated_jp_ip["stages"], ["jp-manual"])
            self.assertIn("DOMAIN-SUFFIX,jp.example", populated.files[populated_jp["path"]].decode())
            self.assertIn("IP-CIDR,198.51.100.0/24", populated.files[populated_jp_ip["path"]].decode())
        personal_profile._require_stable_client_interface(empty.manifest, populated.manifest)

    def test_compact_profile_and_manifest_changes_are_interface_gated(self) -> None:
        baseline = compile_candidate()
        changed = copy.deepcopy(baseline.manifest)
        changed["compact"]["groups"]["mihomo"][0]["action"] = "REJECT"
        with self.assertRaisesRegex(personal_profile.ProfileError, "mihomo compact"):
            personal_profile._require_stable_client_interface(baseline.manifest, changed)
        personal_profile._require_stable_client_interface(baseline.manifest, changed, accept_change=True)

        old_manifest = copy.deepcopy(baseline.manifest)
        del old_manifest["compact"]
        with self.assertRaisesRegex(personal_profile.ProfileError, "compact"):
            personal_profile._require_stable_client_interface(old_manifest, baseline.manifest)
        personal_profile._require_stable_client_interface(old_manifest, baseline.manifest, accept_change=True)

        invalid = profile_value()
        test_slot = next(slot for slot in invalid["compact"]["slots"] if slot["id"] == "test")
        us_slot = next(slot for slot in invalid["compact"]["slots"] if slot["id"] == "us")
        test_slot["dns"] = "jp"
        validated = personal_profile.validate_profile(invalid)
        self.assertEqual(
            next(slot for slot in validated["compact"]["slots"] if slot["id"] == "test")["dns"],
            "jp",
        )
        test_slot["dns"] = "test"
        test_slot["stages"] = ["att-us"]
        us_slot["stages"][0] = "network-test"
        with self.assertRaisesRegex(personal_profile.ProfileError, "dns=test"):
            personal_profile.validate_profile(invalid)


if __name__ == "__main__":
    unittest.main()
