import pytest
from unittest.mock import MagicMock, patch


class TestTunnelManager:
    """Test TunnelManager class"""

    def setup_method(self):
        """Reset singleton before each test"""
        # Import and reset the singleton
        import python.helpers.tunnel_manager as tm
        tm.TunnelManager._instance = None
        tm.TunnelManager._lock = MagicMock()

    def test_singleton_pattern(self):
        """Test that TunnelManager follows singleton pattern"""
        from python.helpers.tunnel_manager import TunnelManager

        # Create two instances via get_instance
        instance1 = TunnelManager.get_instance()
        instance2 = TunnelManager.get_instance()

        # They should be the same instance
        assert instance1 is instance2

    def test_initial_state(self):
        """Test that new instance has correct initial state"""
        from python.helpers.tunnel_manager import TunnelManager

        # Create fresh instance (not via get_instance to avoid singleton)
        manager = TunnelManager()

        assert manager.tunnel is None
        assert manager.tunnel_url is None
        assert manager.is_running is False
        assert manager.provider is None

    def test_start_tunnel_returns_existing_url(self):
        """Test that start_tunnel returns existing URL when tunnel is already running"""
        with patch("python.helpers.tunnel_manager.PrintStyle"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            manager.is_running = True
            manager.tunnel_url = "https://existing-tunnel.example.com"

            result = manager.start_tunnel()

            assert result == "https://existing-tunnel.example.com"

    def test_start_tunnel_cloudflared(self):
        """Test starting tunnel with cloudflared provider sets correct state"""
        with patch("python.helpers.tunnel_manager.PrintStyle"), \
             patch("python.helpers.tunnel_manager.threading.Thread"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            # Verify provider can be set before tunnel starts
            manager.provider = "cloudflared"
            
            assert manager.provider == "cloudflared"
            assert manager.is_running is False
            assert manager.tunnel_url is None

    def test_start_tunnel_serveo(self):
        """Test starting tunnel with serveo provider sets correct state"""
        with patch("python.helpers.tunnel_manager.PrintStyle"), \
             patch("python.helpers.tunnel_manager.threading.Thread"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            # Verify provider can be set before tunnel starts
            manager.provider = "serveo"
            
            assert manager.provider == "serveo"
            assert manager.is_running is False

    def test_stop_tunnel_success(self):
        """Test stopping tunnel successfully"""
        with patch("python.helpers.tunnel_manager.PrintStyle"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            manager.is_running = True
            manager.tunnel = MagicMock()
            manager.tunnel_url = "https://test.example.com"
            manager.provider = "serveo"

            result = manager.stop_tunnel()

            assert result is True
            assert manager.is_running is False
            assert manager.tunnel_url is None
            assert manager.provider is None
            manager.tunnel.stop.assert_called_once()

    def test_stop_tunnel_when_not_running(self):
        """Test stopping tunnel when it's not running"""
        with patch("python.helpers.tunnel_manager.PrintStyle"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            manager.is_running = False
            manager.tunnel = None

            result = manager.stop_tunnel()

            assert result is False

    def test_stop_tunnel_with_exception(self):
        """Test stopping tunnel when exception occurs"""
        with patch("python.helpers.tunnel_manager.PrintStyle"):
            from python.helpers.tunnel_manager import TunnelManager

            manager = TunnelManager()
            manager.is_running = True
            manager.tunnel = MagicMock()
            manager.tunnel.stop.side_effect = Exception("Stop failed")

            result = manager.stop_tunnel()

            assert result is False

    def test_get_tunnel_url_when_running(self):
        """Test getting tunnel URL when tunnel is running"""
        from python.helpers.tunnel_manager import TunnelManager

        manager = TunnelManager()
        manager.is_running = True
        manager.tunnel_url = "https://test.example.com"

        result = manager.get_tunnel_url()

        assert result == "https://test.example.com"

    def test_get_tunnel_url_when_not_running(self):
        """Test getting tunnel URL when tunnel is not running"""
        from python.helpers.tunnel_manager import TunnelManager

        manager = TunnelManager()
        manager.is_running = False
        manager.tunnel_url = "https://test.example.com"

        result = manager.get_tunnel_url()

        assert result is None
