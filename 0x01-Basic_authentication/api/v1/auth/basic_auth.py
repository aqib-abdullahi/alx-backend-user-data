#!/usr/bin/env python3
""" Basic authentication
module
"""
from api.v1.auth.auth import Auth
import base64


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

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """returns decoded value of base64 string
        base64_authorization_header
        """
        if (base64_authorization_header is None
                or not isinstance(base64_authorization_header, str)):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except base64.binascii.Error:
            return None

    def extract_user_credentials(self,
                                 decode_base64_authorization_header: str
                                 ) -> (str, str):
        """returns user email and password form base64
        decoded value
        """
        if (decode_base64_authorization_header is None
                or not isinstance(decode_base64_authorization_header, str)):
            return None, None
        if ":" not in decode_base64_authorization_header:
            return None, None

        user_email, password = decode_base64_authorization_header.split(':', 1)
        return user_email, password
