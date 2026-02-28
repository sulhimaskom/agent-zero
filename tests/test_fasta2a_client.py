#!/usr/bin/env python3
"""
Test script to verify FastA2A agent card routing and authentication.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import asyncio

import pytest

from python.helpers import settings


def get_test_urls():
    """Get the URLs to test based on current settings."""
    try:
        cfg = settings.get_settings()
        token = cfg.get("mcp_server_token", "")

        if not token:
            return None

        base_url = "http://localhost:50101"

        urls = {
            "token_based": f"{base_url}/a2a/t-{token}/.well-known/agent.json",
            "bearer_auth": f"{base_url}/a2a/.well-known/agent.json",
            "api_key_header": f"{base_url}/a2a/.well-known/agent.json",
            "api_key_query": f"{base_url}/a2a/.well-known/agent.json?api_key={token}",
        }

        return {"token": token, "urls": urls}

    except Exception as e:
        return None


def print_test_commands():
    """Print curl commands to test FastA2A authentication."""
    data = get_test_urls()
    if not data:
        return

    data["token"]
    data["urls"]


def print_troubleshooting():
    """Print troubleshooting information."""


def validate_token_format():
    """Validate that the token format is correct."""
    try:
        cfg = settings.get_settings()
        token = cfg.get("mcp_server_token", "")

        if not token:
            return False

        if len(token) != 16:
            pass

        # Check token characters
        if token.isalnum():
            pass
        else:
            pass

        return True

    except Exception as e:
        return False


@pytest.mark.asyncio
async def test_server_connectivity():
    """Test basic server connectivity."""
    try:
        import httpx

        async with httpx.AsyncClient() as client:
            try:
                # Test basic server
                await client.get("http://localhost:50101/", timeout=5.0)
                return True
            except httpx.ConnectError:
                return False
            except Exception as e:
                return False

    except ImportError:
        return None


def main():
    """Main test function."""

    # Validate token
    if not validate_token_format():
        print_troubleshooting()
        return 1

    # Test connectivity if possible
    try:
        connectivity = asyncio.run(test_server_connectivity())

        if connectivity is False:
            print_troubleshooting()
            return 1

    except Exception as e:
        pass

    # Print test commands
    print_test_commands()

    return 0


if __name__ == "__main__":
    sys.exit(main())
