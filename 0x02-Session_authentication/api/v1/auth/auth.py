#!/usr/bin/env python3
"""API Authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Manages API Authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns False
        """
        paths = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        # if path[-1] != "/":
        #    paths += "/"
        # if paths in excluded_paths or path in excluded_paths:
        #   return False
        # return True
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                prefix = excluded_path[:-1]
                if path.startswith(prefix):
                    return False
        paths = [path]
        if not path.endswith("/"):
            paths.append(path + "/")

        for p in paths:
            if p in excluded_paths:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """returns None
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None
        """
        return None
