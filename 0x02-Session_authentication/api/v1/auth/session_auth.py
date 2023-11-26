#!/usr/bin/env python3
""" session authentication
module
"""
from api.v1.auth.auth import Auth
import uuid


class SessionAuth(Auth):
    """Session authentication class
    inheriting from Auth class
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates for a user_id a session id
        """
        if (user_id is None or not isinstance(user_id, str)):
            return
        session_id = str(uuid.uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns user_id based on given session_id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return SessionAuth.user_id_by_session_id.get(session_id, None)
