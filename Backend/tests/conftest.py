import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.connection import get_db

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_db(mocker):
    return mocker.patch('app.db.connection.get_db')