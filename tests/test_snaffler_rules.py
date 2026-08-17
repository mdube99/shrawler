import argparse
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


def _install_import_stubs() -> None:
    impacket_module = types.ModuleType("impacket")
    smbconnection_module = types.ModuleType("impacket.smbconnection")

    class SessionError(Exception):
        pass

    class SMBConnection:
        pass

    smbconnection_module.SMBConnection = SMBConnection
    smbconnection_module.SMB2_DIALECT_002 = 0x202
    smbconnection_module.SMB2_DIALECT_21 = 0x210
    smbconnection_module.SMB_DIALECT = 0x100
    smbconnection_module.SessionError = SessionError

    examples_module = types.ModuleType("impacket.examples")
    utils_module = types.ModuleType("impacket.examples.utils")
    utils_module.parse_target = lambda _: ("", "", "", "")

    colorama_module = types.ModuleType("colorama")
    colorama_module.init = lambda: None
    colorama_module.Fore = types.SimpleNamespace(
        GREEN="",
        YELLOW="",
        RED="",
        BLUE="",
        CYAN="",
        MAGENTA="",
    )
    colorama_module.Style = types.SimpleNamespace(RESET_ALL="")

    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda: None

    requests_module = types.ModuleType("requests")
    requests_module.post = lambda *args, **kwargs: None
    requests_module.exceptions = types.SimpleNamespace(
        RequestException=Exception,
        Timeout=Exception,
        ConnectionError=Exception,
    )

    sys.modules.setdefault("impacket", impacket_module)
    sys.modules.setdefault("impacket.smbconnection", smbconnection_module)
    sys.modules.setdefault("impacket.examples", examples_module)
    sys.modules.setdefault("impacket.examples.utils", utils_module)
    sys.modules.setdefault("colorama", colorama_module)
    sys.modules.setdefault("dotenv", dotenv_module)
    sys.modules.setdefault("requests", requests_module)


_install_import_stubs()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shrawler  # noqa: E402


def _make_args(**overrides):
    base = {
        "target": "domain/user:pass@127.0.0.1",
        "operating_mode": "legacy",
        "verbose": False,
        "scan_profile": "balanced",
        "workers": None,
        "permission_check": None,
        "output_mode": None,
        "metrics": False,
        "read_only": True,
        "skip_share": None,
        "add_share": None,
        "shares": None,
        "hosts_file": None,
        "host": "127.0.0.1",
        "output_dir": ".",
        "nemesis_url": None,
        "nemesis_auth": None,
        "nemesis_project": None,
        "nemesis_mode": "off",
        "nemesis_upload_workers": 2,
        "nemesis_retries": 2,
        "nemesis_queue_size": 100,
        "hashes": None,
        "no_pass": True,
        "k": False,
        "aesKey": None,
        "spider": True,
        "download_ext": None,
        "download_name": None,
        "max_depth": 5,
        "delay": 0,
        "max_file_size": None,
        "max_total_download": None,
        "count_ext": None,
        "count_string": None,
        "unique": False,
        "csv_output": False,
        "json_output": False,
        "snaffler_rules_dir": None,
        "snaffler_interest_level": None,
        "snaffler_max_size_to_grep": 1024 * 1024,
        "snaffler_strict": False,
        "snaffler_no_auto_download": False,
        "snaffler_content_mode": None,
        "max_content_reads": None,
        "content_read_budget": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _build_shrawler(**kwargs):
    args = _make_args(**kwargs)
    with mock.patch.object(argparse.ArgumentParser, "parse_args", return_value=args):
        return shrawler.Shrawler()


class _FakeSMBClient:
    def __init__(self, content_bytes: bytes):
        self.content_bytes = content_bytes
        self.calls = 0

    def getFile(self, share, remote_path, callback):
        _ = share
        _ = remote_path
        self.calls += 1
        callback(self.content_bytes)


class SnafflerRuleTests(unittest.TestCase):
    def test_relayed_content_mode_skips_unrelayed_content_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "ContentRule"
EnumerationScope = "ContentsEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileContentAsString"
WordListType = "Contains"
WordList = ["password"]
Triage = "Red"
                """.strip()
            )
            s = _build_shrawler(
                snaffler_rules_dir=tmp, snaffler_content_mode="relayed"
            )
            client = _FakeSMBClient(b"password")
            context = {
                "host": "host",
                "share_name": "DATA",
                "remote_path": "/file.txt",
                "unc_path": r"\\host\DATA\file.txt",
                "file_name": "file.txt",
                "file_extension": ".txt",
                "size_bytes": 8,
            }

            result = s._evaluate_snaffler_file(client, "DATA", context)

            self.assertEqual(client.calls, 0)
            self.assertEqual(result["candidate_matches"], [])

    def test_all_content_mode_reads_unrelayed_content_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "ContentRule"
EnumerationScope = "ContentsEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileContentAsString"
WordListType = "Contains"
WordList = ["password"]
Triage = "Red"
                """.strip()
            )
            s = _build_shrawler(
                snaffler_rules_dir=tmp, snaffler_content_mode="all"
            )
            client = _FakeSMBClient(b"password")
            context = {
                "host": "host",
                "share_name": "DATA",
                "remote_path": "/file.txt",
                "unc_path": r"\\host\DATA\file.txt",
                "file_name": "file.txt",
                "file_extension": ".txt",
                "size_bytes": 8,
            }

            result = s._evaluate_snaffler_file(client, "DATA", context)

            self.assertEqual(client.calls, 1)
            self.assertEqual(len(result["candidate_matches"]), 1)

    def test_loads_valid_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "InterestingFile"
EnumerationScope = "FileEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileName"
WordListType = "Contains"
WordList = ["secret"]
Triage = "Red"
                """.strip()
            )
            s = _build_shrawler(snaffler_rules_dir=tmp)
            self.assertTrue(s.snaffler_enabled)
            self.assertEqual(len(s.snaffler_rules), 1)
            self.assertIn("InterestingFile", s.snaffler_rule_lookup)

    def test_interest_level_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "LowInterest"
EnumerationScope = "FileEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileName"
WordListType = "Contains"
WordList = ["secret"]
Triage = "Yellow"
InterestLevel = 0
                """.strip()
            )
            s = _build_shrawler(snaffler_rules_dir=tmp, snaffler_interest_level=1)
            self.assertFalse(s.snaffler_enabled)
            self.assertEqual(len(s.snaffler_rules), 0)

    def test_strict_mode_fails_unsupported_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "UnsupportedAction"
EnumerationScope = "FileEnumeration"
MatchAction = "EnterArchive"
MatchLocation = "FileName"
WordListType = "Contains"
WordList = ["archive"]
Triage = "Yellow"
                """.strip()
            )
            with self.assertRaises(ValueError):
                _build_shrawler(snaffler_rules_dir=tmp, snaffler_strict=True)

    def test_relay_and_postmatch_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rules.toml").write_text(
                """
[[ClassifierRules]]
RuleName = "FileRelay"
EnumerationScope = "FileEnumeration"
MatchAction = "Relay"
MatchLocation = "FileName"
WordListType = "Contains"
WordList = ["secret"]
RelayTargets = ["ContentRule"]

[[ClassifierRules]]
RuleName = "ContentRule"
EnumerationScope = "ContentsEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileContentAsString"
WordListType = "Contains"
WordList = ["password"]
Triage = "Red"

[[ClassifierRules]]
RuleName = "PostDiscard"
EnumerationScope = "PostMatch"
MatchAction = "Discard"
MatchLocation = "FileContentAsString"
WordListType = "Contains"
WordList = ["ignore-me"]
                """.strip()
            )

            s = _build_shrawler(snaffler_rules_dir=tmp)
            client = _FakeSMBClient(b"this document contains a password")
            context = {
                "host": "127.0.0.1",
                "share_name": "DATA",
                "remote_path": "/docs/secret.txt",
                "unc_path": r"\\127.0.0.1\DATA\docs\secret.txt",
                "file_name": "secret.txt",
                "file_extension": ".txt",
                "size_bytes": 1024,
            }

            result = s._evaluate_snaffler_file(client, "DATA", context)
            self.assertFalse(result["discarded"])
            self.assertGreaterEqual(len(result["candidate_matches"]), 1)


if __name__ == "__main__":
    unittest.main()
