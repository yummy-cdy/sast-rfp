# TST-007: 분석 결과 관리 시험
import io
import zipfile
from pathlib import Path

from tests.conftest import auth_headers

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _zip_bytes(*file_paths: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path in file_paths:
            z.write(path, path.name)
    return buf.getvalue()


def _analyzed_project(client, admin_token):
    project_res = client.post(
        "/api/projects",
        json={"name": "Results Test", "target_language": "Python"},
        headers=auth_headers(admin_token),
    )
    project_id = project_res.json()["project_id"]
    zip_data = _zip_bytes(FIXTURES_DIR / "vuln_samples" / "vuln.py")
    client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("vuln.zip", zip_data, "application/zip")},
        headers=auth_headers(admin_token),
    )
    analyze_res = client.post(
        f"/api/projects/{project_id}/analyze", headers=auth_headers(admin_token)
    )
    return project_id, analyze_res.json()["execution_id"]


def test_severity_filter_narrows_results(client, admin_token):
    project_id, _ = _analyzed_project(client, admin_token)

    all_res = client.get(f"/api/projects/{project_id}/results", headers=auth_headers(admin_token))
    high_res = client.get(
        f"/api/projects/{project_id}/results?severity=High", headers=auth_headers(admin_token)
    )

    assert len(high_res.json()) < len(all_res.json())
    assert all(r["severity"] == "High" for r in high_res.json())


def test_execution_detail_endpoint(client, admin_token):
    project_id, execution_id = _analyzed_project(client, admin_token)
    res = client.get(f"/api/executions/{execution_id}", headers=auth_headers(admin_token))
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "COMP"
    assert body["summary"]["findings_count"] == 20


def test_execution_results_endpoint_supports_criteria_filter(client, admin_token):
    _, execution_id = _analyzed_project(client, admin_token)
    res = client.get(
        f"/api/executions/{execution_id}/results?criteria_id=KISA-001",
        headers=auth_headers(admin_token),
    )
    body = res.json()
    assert len(body) == 1
    assert body[0]["criteria_id"] == "KISA-001"


def test_diagnostic_result_preserves_criteria_snapshot(client, admin_token):
    """DAR-008: 분석 시점의 진단 항목 식별자/명칭/기준/언어/심각도/신뢰도를 보존한다."""
    project_id, _ = _analyzed_project(client, admin_token)
    res = client.get(f"/api/projects/{project_id}/results", headers=auth_headers(admin_token))
    result = res.json()[0]
    for field in [
        "criteria_id", "criteria_name", "standard_id", "target_language",
        "severity", "confidence", "recommendation",
    ]:
        assert result[field]
