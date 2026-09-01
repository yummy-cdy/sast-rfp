# TST-004: 분석 처리 시험 (소스 수집 -> 언어 식별 -> 구조 분석 -> 진단 실행 -> 결과 표준화)
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


def _create_project(client, admin_token, language="Python"):
    res = client.post(
        "/api/projects",
        json={"name": "Pipeline Test", "target_language": language},
        headers=auth_headers(admin_token),
    )
    assert res.status_code == 201
    return res.json()["project_id"]


def test_full_pipeline_upload_analyze_results(client, admin_token):
    project_id = _create_project(client, admin_token)
    zip_data = _zip_bytes(FIXTURES_DIR / "vuln_samples" / "vuln.py")

    upload_res = client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("vuln.zip", zip_data, "application/zip")},
        headers=auth_headers(admin_token),
    )
    assert upload_res.status_code == 200

    analyze_res = client.post(
        f"/api/projects/{project_id}/analyze", headers=auth_headers(admin_token)
    )
    assert analyze_res.status_code == 200
    assert analyze_res.json()["findings_count"] == 20

    executions_res = client.get(
        f"/api/projects/{project_id}/executions", headers=auth_headers(admin_token)
    )
    executions = executions_res.json()
    assert len(executions) == 1
    assert executions[0]["status"] == "COMP"
    assert executions[0]["engine_type"] == "TREE_SITTER_AST_v1"
    assert executions[0]["executed_by"] == "admin"

    results_res = client.get(
        f"/api/projects/{project_id}/results", headers=auth_headers(admin_token)
    )
    results = results_res.json()
    assert len(results) == 20
    assert all(r["target_language"] == "Python" for r in results)


def test_clean_source_yields_no_findings(client, admin_token):
    project_id = _create_project(client, admin_token)
    zip_data = _zip_bytes(FIXTURES_DIR / "clean_samples" / "clean.py")

    client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("clean.zip", zip_data, "application/zip")},
        headers=auth_headers(admin_token),
    )
    analyze_res = client.post(
        f"/api/projects/{project_id}/analyze", headers=auth_headers(admin_token)
    )
    assert analyze_res.json()["findings_count"] == 0
