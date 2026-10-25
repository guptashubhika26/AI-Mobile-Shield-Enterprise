
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app, Base, get_db


@pytest.fixture
def client():
    # Create a temporary in-memory database for testing
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(bind=test_engine)

    # Create tables in the temporary database
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        with TestingSessionLocal() as session:
            yield session

    # Use the temporary database instead of the real database
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["database"] == "connected"


def test_create_security_event(client):
    payload = {
        "asset_id": "pytest-device-01",
        "source": "automated-test",
        "event_type": "test_login_event",
        "description": "Automated API test event",
        "severity": "medium",
        "simulated": True,
    }

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 201

    body = response.json()
    assert body["message"] == "Security event saved"
    assert body["event"]["event_type"] == "test_login_event"
    assert body["event"]["severity"] == "medium"
    assert body["event"]["simulated"] is True


def test_list_security_events(client):
    response = client.get("/api/v1/events")

    assert response.status_code == 200
    assert "count" in response.json()
    assert "events" in response.json()
    assert isinstance(response.json()["events"], list)


def test_invalid_severity_rejected(client):
    payload = {
        "asset_id": "pytest-device-02",
        "source": "automated-test",
        "event_type": "invalid_severity_test",
        "description": "This event should be rejected",
        "severity": "extreme",
        "simulated": True,
    }

    response = client.post("/api/v1/events", json=payload)

    assert response.status_code == 422
