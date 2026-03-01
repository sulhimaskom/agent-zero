"""GUID/ID generation utilities for Agent Zero.

Provides functions for generating short random identifiers used throughout
the framework for unique IDs, session IDs, and other identificators.
"""

import secrets
import string


def generate_id(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
