# TST-002/003: 역할 권한 시험, 프로젝트 접근 시험
from tests.conftest import auth_headers


def _create_project(client, admin_token, name="RBAC Test Project"):
    res = client.post(
        "/api/projects",
        json={"name": name, "target_language": "Python"},
        headers=auth_headers(admin_token),
    )
    assert res.status_code == 201
    return res.json()["project_id"]


def test_general_user_cannot_create_project(client, user_token):
    res = client.post(
        "/api/projects",
        json={"name": "x", "target_language": "Python"},
        headers=auth_headers(user_token),
    )
    assert res.status_code == 403


def test_admin_can_create_and_list_project(client, admin_token):
    project_id = _create_project(client, admin_token)
    res = client.get("/api/projects", headers=auth_headers(admin_token))
    assert res.status_code == 200
    assert any(p["project_id"] == project_id for p in res.json())


def test_unassigned_user_cannot_see_project_in_list(client, admin_token, user_token):
    _create_project(client, admin_token)
    res = client.get("/api/projects", headers=auth_headers(user_token))
    assert res.status_code == 200
    assert res.json() == []


def test_unassigned_user_gets_404_not_403_on_direct_access(client, admin_token, user_token):
    """SEC-006: 권한 없는 사용자에게는 자원 존재 여부를 노출하지 않는다."""
    project_id = _create_project(client, admin_token)
    res = client.get(f"/api/projects/{project_id}", headers=auth_headers(user_token))
    assert res.status_code == 404


def test_granted_user_can_view_but_not_modify(client, admin_token, user_token):
    project_id = _create_project(client, admin_token)

    grant_res = client.post(
        f"/api/projects/{project_id}/permissions",
        json={"user_id": "tester1"},
        headers=auth_headers(admin_token),
    )
    assert grant_res.status_code == 201

    view_res = client.get(f"/api/projects/{project_id}", headers=auth_headers(user_token))
    assert view_res.status_code == 200

    analyze_res = client.post(
        f"/api/projects/{project_id}/analyze", headers=auth_headers(user_token)
    )
    assert analyze_res.status_code == 403

    upload_res = client.post(
        f"/api/projects/{project_id}/source",
        files={"file": ("x.zip", b"not-a-real-zip", "application/zip")},
        headers=auth_headers(user_token),
    )
    assert upload_res.status_code == 403


def test_revoked_permission_removes_access(client, admin_token, user_token):
    project_id = _create_project(client, admin_token)
    client.post(
        f"/api/projects/{project_id}/permissions",
        json={"user_id": "tester1"},
        headers=auth_headers(admin_token),
    )
    client.delete(
        f"/api/projects/{project_id}/permissions/tester1", headers=auth_headers(admin_token)
    )

    res = client.get(f"/api/projects/{project_id}", headers=auth_headers(user_token))
    assert res.status_code == 404


def test_admin_bypasses_permission_check(client, admin_token):
    project_id = _create_project(client, admin_token)
    res = client.get(f"/api/projects/{project_id}", headers=auth_headers(admin_token))
    assert res.status_code == 200
