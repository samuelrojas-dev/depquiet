"""Exercise the real OSV batch contract: ID stubs followed by detail lookups."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.request import Request

import pytest

from depquiet.cli import _should_fail
from depquiet.engine import scan
from depquiet.models import Severity
from depquiet.parsers.osv import (
    _cvss3_base_score,
    _osv_severity,
    parse_osv_response,
    query_osv_batch,
)
from depquiet.scanners import ScanError


def _response(data: object) -> io.BytesIO:
    return io.BytesIO(json.dumps(data).encode())


def _detail(vuln_id: str = "GHSA-example") -> dict[str, Any]:
    return {
        "id": vuln_id,
        "aliases": ["CVE-2024-12345"],
        "summary": "Command injection in widget",
        "database_specific": {"severity": "HIGH"},
        "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
        "affected": [
            {
                "package": {"name": "widget", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
            }
        ],
    }


def test_batch_ids_are_hydrated_before_triage(tmp_path: Path) -> None:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "widget", "version": "1.0", "purl": "pkg:npm/widget@1.0"}],
    }
    with (
        patch(
            "depquiet.parsers.osv.urllib.request.urlopen",
            side_effect=[
                _response(
                    {"results": [{"vulns": [{"id": "GHSA-example", "modified": "2024-01-01"}]}]}
                ),
                _response(_detail()),
            ],
        ) as urlopen,
        patch("depquiet.engine.EpssFilter.lookup"),
    ):
        result = scan(tmp_path, audit_json=sbom)
    vuln = result.results[0].vuln
    assert vuln.cve == "CVE-2024-12345"
    assert vuln.severity == Severity.HIGH
    assert vuln.title == "Command injection in widget"
    assert vuln.fix_version == "2.0"
    assert vuln.url == "https://example.com/advisory"
    assert _should_fail(result, "high") is True
    assert urlopen.call_args_list[0].args[0].get_method() == "POST"
    assert urlopen.call_args_list[1].args[0].full_url.endswith("/v1/vulns/GHSA-example")


def test_detail_fetch_failure_does_not_return_partial_findings() -> None:
    with (
        patch(
            "depquiet.parsers.osv.urllib.request.urlopen",
            side_effect=[
                _response({"results": [{"vulns": [{"id": "GHSA-example"}]}]}),
                OSError("detail lookup failed"),
            ],
        ),
        pytest.raises(ScanError, match="detail lookup failed"),
    ):
        query_osv_batch([("widget", "1.0", "npm")])


@pytest.mark.parametrize("data", [{}, {"results": []}, {"results": [None]}, {"error": "failed"}])
def test_malformed_batch_response_is_not_a_clean_scan(data: object) -> None:
    with (
        patch("depquiet.parsers.osv.urllib.request.urlopen", return_value=_response(data)),
        pytest.raises(ScanError),
    ):
        query_osv_batch([("widget", "1.0", "npm")])


def test_wrong_detail_id_is_scan_error() -> None:
    with (
        patch(
            "depquiet.parsers.osv.urllib.request.urlopen",
            side_effect=[
                _response({"results": [{"vulns": [{"id": "GHSA-example"}]}]}),
                _response(_detail("GHSA-wrong")),
            ],
        ),
        pytest.raises(ScanError, match="invalid record"),
    ):
        query_osv_batch([("widget", "1.0", "npm")])


def test_pagination_preserves_package_positions_and_reuses_details() -> None:
    requests: list[Request] = []
    responses = [
        {
            "results": [
                {"vulns": [{"id": "GHSA-example"}], "next_page_token": "page-2"},
                {"vulns": [{"id": "GHSA-example"}]},
            ]
        },
        _detail(),
        {"results": [{"vulns": [{"id": "GHSA-second"}]}]},
        _detail("GHSA-second"),
    ]

    def respond(req: Request, **kwargs: Any) -> io.BytesIO:
        requests.append(req)
        return _response(responses[len(requests) - 1])

    with patch("depquiet.parsers.osv.urllib.request.urlopen", side_effect=respond):
        result = query_osv_batch([("widget", "1.0", "npm"), ("widget", "1.1", "npm")])
    assert [v["id"] for v in result["results"][0]["vulns"]] == ["GHSA-example", "GHSA-second"]
    assert [v["id"] for v in result["results"][1]["vulns"]] == ["GHSA-example"]
    next_query = json.loads(requests[2].data or b"{}")
    assert next_query["queries"] == [
        {
            "version": "1.0",
            "package": {"name": "widget", "ecosystem": "npm"},
            "page_token": "page-2",
        }
    ]
    assert len(requests) == 4


def test_repeated_pagination_token_is_scan_error() -> None:
    with (
        patch(
            "depquiet.parsers.osv.urllib.request.urlopen",
            side_effect=[
                _response({"results": [{"next_page_token": "same"}]}),
                _response({"results": [{"next_page_token": "same"}]}),
            ],
        ),
        pytest.raises(ScanError, match="pagination token"),
    ):
        query_osv_batch([("widget", "1.0", "npm")])


def test_large_inventory_is_batched_without_omitting_packages() -> None:
    sizes: list[int] = []

    def respond(req: Request, **kwargs: Any) -> io.BytesIO:
        queries = json.loads(req.data or b"{}")["queries"]
        sizes.append(len(queries))
        return _response({"results": [{} for _ in queries]})

    packages = [(f"package-{i}", "1.0", "npm") for i in range(1001)]
    with patch("depquiet.parsers.osv.urllib.request.urlopen", side_effect=respond):
        response = query_osv_batch(packages)
    assert sizes == [1000, 1]
    assert len(response["results"]) == len(packages)
    assert parse_osv_response(response, packages) == []


@pytest.mark.parametrize(
    ("vector", "score", "severity"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, Severity.HIGH),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, Severity.MODERATE),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Severity.MODERATE),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.INFO),
    ],
)
def test_cvss3_vectors_retain_base_severity(vector: str, score: float, severity: Severity) -> None:
    assert _cvss3_base_score(vector) == score
    assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": vector}]}) == severity


def test_cvss3_metric_order_and_temporal_metrics_do_not_lower_base() -> None:
    vector = "CVSS:3.1/S:U/C:H/A:H/I:H/UI:N/PR:N/AC:L/AV:N/E:U/RL:O/RC:U"
    assert _cvss3_base_score(vector) == 9.8


def test_unknown_vector_without_declared_severity_does_not_silently_become_moderate() -> None:
    """Unknown, not moderate, and not the end of the scan (textual, 2026-11-27)."""
    assert _osv_severity({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}]}) is None


def test_an_advisory_with_an_unscorable_vector_is_kept_as_unknown_severity() -> None:
    response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "PYSEC-2026-4320",
                        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}],
                        "affected": [
                            {
                                "package": {"name": "x"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2"}]}],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    (vuln,) = parse_osv_response(response, [("x", "1", "PyPI")])
    assert vuln.severity_known is False
    assert vuln.severity_label == "unknown"
    assert vuln.fix_version == "2"


def test_declared_severity_supported_without_scoring_unknown_vector() -> None:
    assert (
        _osv_severity(
            {
                "database_specific": {"severity": "CRITICAL"},
                "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}],
            }
        )
        == Severity.CRITICAL
    )
