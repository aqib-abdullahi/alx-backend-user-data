#!/usr/bin/env python3
""" Basic authentication
module
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic auth class inheriting from
    auth class
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns base64 part of authorization header
        for basic authentication
        """
        if not authorization_header:
            return None
        elif not isinstance(authorization_header, str):
            return None
        elif not authorization_header.startswith("Basic "):
            return None
        else:
            return authorization_header[6:]
