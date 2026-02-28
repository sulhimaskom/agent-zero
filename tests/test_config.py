"""Tests for config module - frontend configuration injection.

These tests verify the configuration functions for frontend injection.
"""


from python.helpers.config import (
    get_env_config_js,
    get_frontend_config,
    inject_config_into_html,
)


class TestGetFrontendConfig:
    """Tests for get_frontend_config function"""

    def test_get_frontend_config_returns_dict(self):
        """Test that get_frontend_config returns a dictionary"""
        result = get_frontend_config()
        assert isinstance(result, dict)

    def test_get_frontend_config_has_network_keys(self):
        """Test that result contains network configuration keys"""
        result = get_frontend_config()

        # Network configuration
        assert "WEB_UI_PORT" in result
        assert "TUNNEL_API_PORT" in result
        assert "SEARXNG_PORT" in result
        assert "A2A_PORT" in result
        assert "BROCULA_PORT" in result
        assert "RFC_PORT_HTTP" in result
        assert "RFC_PORT_SSH" in result

    def test_get_frontend_config_has_host_keys(self):
        """Test that result contains host configuration keys"""
        result = get_frontend_config()

        # Host configuration
        assert "HOSTNAME" in result
        assert "LOCALHOST" in result

    def test_get_frontend_config_has_url_keys(self):
        """Test that result contains URL configuration keys"""
        result = get_frontend_config()

        # External URLs
        assert "AGENT_ZERO_REPO_URL" in result
        assert "UPDATE_CHECK_URL" in result

    def test_get_frontend_config_has_features(self):
        """Test that result contains feature flags"""
        result = get_frontend_config()

        assert "FEATURES" in result
        features = result["FEATURES"]
        assert isinstance(features, dict)
        assert "mcp_enabled" in features
        assert "a2a_enabled" in features
        assert "tunnel_enabled" in features
        assert "speech_enabled" in features
        # All features should be booleans
        assert all(isinstance(v, bool) for v in features.values())

    def test_get_frontend_config_has_limits(self):
        """Test that result contains limit values"""
        result = get_frontend_config()

        assert "LIMITS" in result
        limits = result["LIMITS"]
        assert isinstance(limits, dict)
        assert "max_attachment_size" in limits
        assert "max_file_size" in limits
        assert "max_message_length" in limits

    def test_get_frontend_config_has_static_ports(self):
        """Test that result contains static ports"""
        result = get_frontend_config()

        assert "STATIC_PORTS" in result

    def test_get_frontend_config_ports_are_integers(self):
        """Test that port values are integers"""
        result = get_frontend_config()

        port_keys = ["WEB_UI_PORT", "TUNNEL_API_PORT", "SEARXNG_PORT", "A2A_PORT",
                     "BROCULA_PORT", "RFC_PORT_HTTP", "RFC_PORT_SSH"]

        for key in port_keys:
            assert isinstance(result[key], int), f"{key} should be an integer"


class TestGetEnvConfigJs:
    """Tests for get_env_config_js function"""

    def test_get_env_config_js_returns_string(self):
        """Test that get_env_config_js returns a string"""
        result = get_env_config_js()
        assert isinstance(result, str)

    def test_get_env_config_js_contains_script_tag(self):
        """Test that result contains script tag"""
        result = get_env_config_js()

        assert "<script>" in result
        assert "</script>" in result

    def test_get_env_config_js_sets_window_env_config(self):
        """Test that result sets window.ENV_CONFIG"""
        result = get_env_config_js()

        assert "window.ENV_CONFIG" in result

    def test_get_env_config_js_is_valid_javascript(self):
        """Test that result contains valid JavaScript assignment"""
        result = get_env_config_js()

        # Should contain assignment to window.ENV_CONFIG
        assert "window.ENV_CONFIG = " in result

    def test_get_env_config_js_contains_json(self):
        """Test that result contains JSON configuration"""
        result = get_env_config_js()

        # Should contain JSON representation
        assert "{" in result
        assert "}" in result


class TestInjectConfigIntoHtml:
    """Tests for inject_config_into_html function"""

    def test_inject_config_into_html_returns_string(self):
        """Test that inject_config_into_html returns a string"""
        result = inject_config_into_html("<html><head></head></html>")
        assert isinstance(result, str)

    def test_inject_config_into_html_adds_script(self):
        """Test that config script is injected into HTML"""
        html = "<html><head></head></html>"
        result = inject_config_into_html(html)

        assert "<script>" in result

    def test_inject_config_into_html_before_head_close(self):
        """Test that script is injected before </head>"""
        html = "<html><head></head></html>"
        result = inject_config_into_html(html)

        # Script should appear before </head>
        assert result.index("<script>") < result.index("</head>")

    def test_inject_config_into_html_no_head_tag(self):
        """Test behavior when no </head> tag exists"""
        html = "<html><body></body></html>"
        result = inject_config_into_html(html)

        # Should return original content unchanged
        assert result == html

    def test_inject_config_into_html_multiple_head_tags(self):
        """Test behavior with multiple </head> tags"""
        html = "<html><head><title>Test</title></head><body></body></html>"
        result = inject_config_into_html(html)

        # Should inject before first </head>
        assert result.count("<script>") == 1

    def test_inject_config_into_html_empty_string(self):
        """Test behavior with empty HTML"""
        result = inject_config_into_html("")

        # Should return unchanged
        assert result == ""

    def test_inject_config_into_html_preserves_original_content(self):
        """Test that original HTML content is preserved"""
        original = '<html><head><title>My Title</title></head><body>Content</body></html>'
        result = inject_config_into_html(original)

        # Original content should be preserved
        assert "My Title" in result
        assert "Content" in result
        assert "</head>" in result

    def test_inject_config_into_html_has_window_env_config(self):
        """Test that injected script contains window.ENV_CONFIG"""
        html = "<html><head></head></html>"
        result = inject_config_into_html(html)

        assert "window.ENV_CONFIG" in result


class TestConfigIntegration:
    """Integration tests for config module"""

    def test_frontend_config_matches_js_config(self):
        """Test that get_frontend_config data matches what's in JS output"""
        config_dict = get_frontend_config()
        js_output = get_env_config_js()

        # JS should contain all the keys from config dict
        for key in config_dict:
            assert key in js_output

    def test_injected_html_contains_full_config(self):
        """Test that injected HTML contains complete configuration"""
        html = "<html><head></head></html>"
        result = inject_config_into_html(html)

        # Should contain network config keys
        assert "WEB_UI_PORT" in result
        # Should contain feature flags
        assert "mcp_enabled" in result
        # Should contain limits
        assert "max_attachment_size" in result
