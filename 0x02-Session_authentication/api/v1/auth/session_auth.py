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
        SessionAuth.user_id_by_session_id[user_id] = session_id
        return session_id
