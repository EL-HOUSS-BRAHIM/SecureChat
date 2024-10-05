# tests/test_session_manager.py
from app.services.session_manager import SessionManager

def test_create_session():
    manager = SessionManager()
    manager.create_session(user_id=1)

    assert 1 in manager.active_sessions

def test_revoke_all_sessions():
    manager = SessionManager()
    manager.create_session(user_id=1)
    manager.create_session(user_id=2)

    manager.revoke_all_sessions(1)

    assert 1 not in manager.active_sessions
    assert 2 in manager.active_sessions
