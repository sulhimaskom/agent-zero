"""GUID/ID generation utilities for Agent Zero.

Provides functions for generating short random identifiers used throughout
the framework for unique IDs, session IDs, and other identificators.
"""

import random
import string


def generate_id(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))
