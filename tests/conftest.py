import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from database import get_db
from main import app
from core.security import get_password_hash
from engine.kisa_catalog import catalog_rows

TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture()
def db_session():
    models.Base.metadata.create_all(bind=TEST_ENGINE)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        models.Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture()
def client(db_session, tmp_path, monkeypatch):
    import routers.analysis as analysis_module

    # 테스트가 실제 프로젝트의 uploads/ 디렉터리를 오염시키지 않도록 격리한다.
    monkeypatch.setattr(analysis_module, "UPLOAD_DIR", str(tmp_path / "uploads"))

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_credentials(db_session):
    user = models.User(
        user_id="admin",
        password_hash=get_password_hash("admin1234!"),
        role="ADMIN",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return {"user_id": "admin", "password": "admin1234!"}


@pytest.fixture()
def user_credentials(db_session):
    user = models.User(
        user_id="tester1",
        password_hash=get_password_hash("testpass123"),
        role="USER",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return {"user_id": "tester1", "password": "testpass123"}


@pytest.fixture()
def admin_token(client, admin_credentials):
    res = client.post("/api/auth/login", json=admin_credentials)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture()
def user_token(client, user_credentials):
    res = client.post("/api/auth/login", json=user_credentials)
    assert res.status_code == 200
    return res.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def seeded_criteria(db_session):
    for row in catalog_rows():
        db_session.add(models.DiagnosticCriteria(**row))
    db_session.commit()
