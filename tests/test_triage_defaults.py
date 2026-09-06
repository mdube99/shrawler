"""Operator-purpose ranking and a bounded extension-only review pool."""

import json
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import pytest

from shrawler.collection import CollectionQueue
from shrawler.store import ScanStore
from shrawler.triage.cli import main
from shrawler.triage.engine import Engine
from shrawler.triage.review import ReviewStore
from shrawler.triage.rules import load
from shrawler.triage.storage import catalog, list_results, rank

from .test_triage import metadata


@pytest.mark.parametrize(
    "name",
    [
        "AD Join.ps1",
        "DomainJoin.ps1",
        "domainjoin.ps1",
        "Install.ps1",
        "INSTALL.BAT",
        "Install-Application.ps1",
        "Provision.ps1",
        "Deploy.ps1",
        "Map Drive.ps1",
        "MapDrive.ps1",
        "Backup.ps1",
        "Scheduled Task.ps1",
    ],
)
def test_operational_script_names_rank_between_fallback_and_credentials(name):
    engine = Engine(load())
    result = engine.evaluate(metadata("/" + name))
    assert result["priority"] == 10
    assert engine.evaluate(metadata("/credentials.ps1"))["priority"] == 30
    assert "operational" in next(
        signal["rule_id"] for signal in result["signals"] if signal["credited_points"]
    )


@pytest.mark.parametrize("extension", ["config", "ini", "bat", "ps1", "json", "xml"])
def test_extension_only_is_zero_priority_but_explained(extension):
    result = Engine(load()).evaluate(metadata("/123." + extension))
    assert result["priority"] == 0
    assert result["category_scores"] == {"extension-fallback": 0}
    assert result["signals"][0]["evidence"]["extension_any"] == ["." + extension]


def test_bounded_context_strengthens_scripts_without_double_counting():
    engine = Engine(load())
    result = engine.evaluate(metadata("/Deployment/Orion/Install.ps1"))
    assert result["priority"] == 20
    assert sum(signal["credited_points"] for signal in result["signals"]) == 20
    context = next(s for s in result["signals"] if s["credited_points"] == 20)
    assert context["evidence"]["context_sources"][0]["source_path"] == "/Deployment"
    assert engine.evaluate(metadata("/Deployment/a/b/Install.ps1"))["priority"] == 10
    assert engine.evaluate(metadata("/Deployment/123.ps1"))["priority"] == 20
    assert engine.evaluate(metadata("/Deployment/production.xml"))["priority"] == 50


def test_name_signals_retain_other_formats_and_separate_sensitive_categories():
    engine = Engine(load())
    for name, category, score in [
        ("passwords.xlsx", "credentials", 25),
        ("cred-backup.csv", "credentials", 15),
        ("credit-card-export.csv", "payment-data", 30),
        ("employee-ssn.xlsx", "personal-information", 25),
        ("social_security.csv", "personal-information", 25),
        ("compass.txt", "credentials", 15),
    ]:
        result = engine.evaluate(metadata("/" + name))
        assert result["priority"] == score
        assert result["category_scores"][category] == score
    for name in ("package.json", "Install.txt", "passageway.txt.json", "mapping.txt"):
        result = engine.evaluate(metadata("/" + name))
        assert not any(
            signal["signal_group"] == "operational-purpose"
            for signal in result["signals"]
        )


def test_fallback_pool_cli_pagination_reviews_and_collection(tmp_path):
    with ScanStoreForTest(tmp_path) as scan:
        for name in [
            "a.ps1",
            "b.json",
            "c.xml",
            "Install.ps1",
            "credentials.json",
            "notes.txt",
        ]:
            scan.add_file("server", "DATA", metadata("/" + name))
    database = tmp_path / "shrawler.db"
    with patch(
        "socket.socket", side_effect=AssertionError("offline workflow used network")
    ):
        ranked = rank(database, load())
        assert "extension-fallback" in catalog(database)["runs"][0]["categories"]
        first = list_results(database, category="extension-fallback", limit=2)
        second = list_results(
            database, category="extension-fallback", limit=2, after=first["next_cursor"]
        )
        assert {i["file_name"] for i in first["items"] + second["items"]} == {
            "a.ps1",
            "b.json",
            "c.xml",
        }
        assert second["next_cursor"] is None
        assert (
            list_results(database, category="extension-fallback", min_score=1)["items"]
            == []
        )
        output = StringIO()
        with redirect_stdout(output):
            assert (
                main(
                    [
                        "list",
                        str(database),
                        "--category",
                        "extension-fallback",
                        "--json",
                    ]
                )
                == 0
            )
        assert len(json.loads(output.getvalue())["items"]) == 3
        queue = CollectionQueue(database)
        manifest = queue.create(
            run_id=ranked["run_id"], category="extension-fallback", limit=2
        )
        assert manifest["expected_files"] == 2
        assert all(
            "fallback review" in item["reasons"][0] for item in manifest["items"]
        )
        review = ReviewStore(database)
        review.build()
        review.decide("file", first["items"][0]["file_id"], "reviewed")
        rank(database, load())
        assert len(list_results(database, category="extension-fallback")["items"]) == 2
        # Decisions do not alter a previously saved ranking or its pool.
        assert (
            len(
                list_results(database, ranked["run_id"], category="extension-fallback")[
                    "items"
                ]
            )
            == 3
        )


class ScanStoreForTest:
    def __init__(self, root):
        self.store = ScanStore(root, "spider")

    def __enter__(self):
        self.store.upsert_host("server", "server", "complete")
        self.store.upsert_share("server", "DATA", "complete", {})
        return self.store

    def __exit__(self, *args):
        self.store.finish("completed", {})
        self.store.close()
