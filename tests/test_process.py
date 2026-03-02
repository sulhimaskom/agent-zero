"""Tests for process helper module.

Tests the process management functions for server state.
These tests can run with or without pytest.
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_tests():
    """Run all tests and report results."""
    from python.helpers import process
    from unittest.mock import patch, Mock

    passed = 0
    failed = 0

    # Test 1: set_server and get_server
    print("Test 1: test_set_server_and_get_server")
    try:
        # Create a mock server object
        mock_server = Mock()

        # Set the server
        process.set_server(mock_server)

        # Get the server and verify it's the same
        retrieved = process.get_server(mock_server)
        assert retrieved is mock_server, "Retrieved server should be the same as mock_server"

        # Clean up
        process._server = None
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Test 2: get_server returns None when not set
    print("Test 2: test_get_server_returns_none_when_not_set")
    try:
        # Ensure no server is set
        process._server = None

        # get_server should return None
        result = process.get_server("any_arg")
        assert result is None, "Should return None when no server is set"
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Test 3: stop_server cleans up
    print("Test 3: test_stop_server_cleans_up")
    try:
        # Create and set a mock server
        mock_server = Mock()
        process.set_server(mock_server)

        # Stop the server
        process.stop_server()

        # Server should be None now
        assert process._server is None, "Server should be None after stop_server"
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Test 4: stop_server handles None gracefully
    print("Test 4: test_stop_server_handles_none")
    try:
        # Ensure no server is set
        process._server = None

        # Should not raise an error
        process.stop_server()

        # Server should still be None
        assert process._server is None, "Server should still be None"
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Test 5: reload checks dockerized
    print("Test 5: test_reload_checks_dockerized")
    try:
        # Mock the runtime.is_dockerized to return False
        with patch("python.helpers.process.runtime.is_dockerized", return_value=False):
            # Mock stop_server to prevent actual server shutdown
            with patch.object(process, "stop_server"):
                # Mock restart_process to prevent process restart
                with patch.object(process, "restart_process") as mock_restart:
                    # Call reload - should call restart_process when not dockerized
                    process.reload()
                    mock_restart.assert_called_once()
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Test 6: reload calls exit in docker
    print("Test 6: test_reload_calls_exit_in_docker")
    try:
        # Mock the runtime.is_dockerized to return True
        with patch("python.helpers.process.runtime.is_dockerized", return_value=True):
            # Mock stop_server to prevent actual server shutdown
            with patch.object(process, "stop_server"):
                # Mock exit_process to prevent sys.exit
                with patch.object(process, "exit_process") as mock_exit:
                    # Call reload - should call exit_process when dockerized
                    process.reload()
                    mock_exit.assert_called_once()
        print("  PASSED")
        passed += 1
    except Exception as e:
        print(f"  FAILED: {e}")
        failed += 1

    # Summary
    print(f"\n{'=' * 50}")
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"{'=' * 50}")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
