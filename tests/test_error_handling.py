# TST-008: 오류 처리 시험
import io
import zipfile

from tests.conftest import auth_headers


def _create_project(client, admin_token):
    res = client.post(
        "/api/projects",
        json={"name": "Error Test", "target_language": "Python"},
        headers=auth_headers(admin_token),
    )
    return res.json()["project_id"]


def test_analyze_without_source_returns_400(client, admin_token):
    project_id = _create_project(client, admin_token)
    res = client.post(f"/api/projects/{project_id}/analyze", headers=auth_headers(admin_token))
    assert res.status_code == 400
    assert res.json()["detail"]


def test_upload_invalid_zip_returns_400(client, admin_token):
    project_id = _create_project(client, admin_token)
    res = client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("broken.zip", b"this is not a zip file", "application/zip")},
        headers=auth_headers(admin_token),
    )
    assert res.status_code == 400


def test_upload_path_traversal_zip_returns_400(client, admin_token):
    project_id = _create_project(client, admin_token)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil.py", "print('escaped')")

    res = client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
        headers=auth_headers(admin_token),
    )
    assert res.status_code == 400
    assert "경로" in res.json()["detail"]


def test_analyze_nonexistent_project_returns_400(client, admin_token):
    res = client.post("/api/projects/999999/analyze", headers=auth_headers(admin_token))
    assert res.status_code == 400


def test_results_for_project_without_analysis_is_empty_list(client, admin_token):
    project_id = _create_project(client, admin_token)
    res = client.get(f"/api/projects/{project_id}/results", headers=auth_headers(admin_token))
    assert res.status_code == 200
    assert res.json()["items"] == []
    assert res.json()["total"] == 0


def test_get_project_not_found_returns_404(client, admin_token):
    res = client.get("/api/projects/999999", headers=auth_headers(admin_token))
    assert res.status_code == 404
