# TST-005/006: 진단 항목 시험, 개발보안 가이드 진단 기준 카탈로그 시험
from pathlib import Path

import pytest

from engine.scanner import run_analysis
from engine.kisa_catalog import catalog_rows
from tests.conftest import auth_headers

FIXTURES_DIR = Path(__file__).parent / "fixtures"

EXPECTED_VULN_CRITERIA = {
    "Python": {
        "KISA-001", "KISA-002", "KISA-004", "KISA-006", "KISA-011", "KISA-014",
        "KISA-018", "KISA-020", "KISA-021", "KISA-022", "KISA-032", "KISA-037",
        "KISA-042", "KISA-046",
    },
    "Javascript": {"KISA-001", "KISA-003", "KISA-004", "KISA-014", "KISA-020", "KISA-021", "KISA-032"},
    "Java": {"KISA-001", "KISA-002", "KISA-004", "KISA-018", "KISA-020", "KISA-021", "KISA-032"},
}


@pytest.mark.parametrize("language", ["Python", "Javascript", "Java"])
def test_vuln_samples_detect_expected_criteria(language):
    results = run_analysis(str(FIXTURES_DIR / "vuln_samples"), language)
    found_ids = {r["criteria_id"] for r in results}
    assert found_ids == EXPECTED_VULN_CRITERIA[language]

    for r in results:
        assert r["line_number"] > 0
        assert r["evidence"]
        assert r["recommendation"]
        assert r["severity"] in {"High", "Medium", "Low"}


@pytest.mark.parametrize("language", ["Python", "Javascript", "Java"])
def test_clean_samples_yield_no_findings(language):
    results = run_analysis(str(FIXTURES_DIR / "clean_samples"), language)
    assert results == []


def test_kisa_catalog_has_49_items():
    rows = catalog_rows()
    assert len(rows) == 49
    assert len({r["criteria_id"] for r in rows}) == 49


def test_kisa_catalog_marks_implemented_rules():
    rows = {r["criteria_id"]: r for r in catalog_rows()}
    for criteria_id in EXPECTED_VULN_CRITERIA["Python"]:
        assert rows[criteria_id]["implementation_status"] == "IMPLEMENTED"


def test_criteria_api_returns_49_items(client, admin_token, seeded_criteria):
    res = client.get("/api/criteria", headers=auth_headers(admin_token))
    assert res.status_code == 200
    assert len(res.json()) == 49


def test_criteria_api_filters_by_implementation_status(client, admin_token, seeded_criteria):
    res = client.get(
        "/api/criteria?implementation_status=IMPLEMENTED", headers=auth_headers(admin_token)
    )
    body = res.json()
    assert len(body) == 15
    assert all(item["implementation_status"] == "IMPLEMENTED" for item in body)
