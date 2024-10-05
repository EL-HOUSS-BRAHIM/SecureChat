# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.connection import get_db
from app.models import Base  # Import your database models

# Test DB URL (use an in-memory SQLite database for tests)
TEST_DATABASE_URL = "sqlite:///:memory:"

# Set up test database engine and session
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db dependency with a session for testing
@pytest.fixture(scope="module")
def test_db():
    Base.metadata.create_all(bind=engine)  # Create tables for test DB
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)  # Drop tables after tests are done

# Test client for making requests
@pytest.fixture(scope="module")
def client():
    def override_get_db():
        yield from test_db()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
