# TST-001: 인증 기능 시험
from tests.conftest import auth_headers


def test_login_success_returns_token(client, admin_credentials):
    res = client.post("/api/auth/login", json=admin_credentials)
    assert res.status_code == 200
    body = res.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password_rejected(client, admin_credentials):
    res = client.post(
        "/api/auth/login", json={"user_id": admin_credentials["user_id"], "password": "wrong"}
    )
    assert res.status_code == 401


def test_login_unknown_user_rejected(client):
    res = client.post("/api/auth/login", json={"user_id": "nobody", "password": "x"})
    assert res.status_code == 401


def test_protected_endpoint_without_token_is_blocked(client):
    res = client.get("/api/projects")
    assert res.status_code == 401


def test_protected_endpoint_with_invalid_token_is_blocked(client):
    res = client.get("/api/projects", headers=auth_headers("not-a-real-token"))
    assert res.status_code == 401


def test_protected_endpoint_with_valid_token_succeeds(client, admin_token):
    res = client.get("/api/auth/me", headers=auth_headers(admin_token))
    assert res.status_code == 200
    assert res.json()["role"] == "ADMIN"


def test_inactive_account_is_blocked(client, db_session, admin_token):
    import models

    user = db_session.query(models.User).filter(models.User.user_id == "admin").first()
    user.is_active = False
    db_session.commit()

    res = client.get("/api/auth/me", headers=auth_headers(admin_token))
    assert res.status_code == 401
