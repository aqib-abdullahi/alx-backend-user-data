#!/usr/bin/env python3
""" Basic authentication
module
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar
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

    def user_object_from_credentials(self,
                                     user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """returns the User instance based on email
        and password
        """
        if (user_email is None or
                not isinstance(user_email, str) or
                user_pwd is None or not isinstance(user_pwd, str)):
            return None
        found_users = User.search({"email": user_email})
        if not found_users:
            return None
        user = found_users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        if request is None:
            return None

        authorization_header = request.headers.get('Authorization')

        if (not authorization_header or
                not authorization_header.startswith('Basic ')):
            return None

        base64_auth_header = authorization_header.split(' ')[1]
        dah = self.decode_base64_authorization_header(base64_auth_header)

        user_email, user_pwd = self.extract_user_credentials(dah)

        user = self.user_object_from_credentials(user_email, user_pwd)

        return user
