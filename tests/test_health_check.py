"""Tests for health_check module"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime

import pytest

from python.helpers.health_check import (
    Diagnostics,
    HealthChecker,
    HealthCheckResult,
    HealthStatus,
    SystemHealth,
    get_health_checker,
    reset_health_checker,
)


class TestHealthStatus:
    """Test HealthStatus enum"""

    def test_health_status_values(self):
        """Test that HealthStatus has correct values"""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestHealthCheckResult:
    """Test HealthCheckResult dataclass"""

    def test_result_creation(self):
        """Test creating a HealthCheckResult"""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            message="Test passed",
            details={"key": "value"},
            response_time_ms=10.5,
        )

        assert result.name == "test_check"
        assert result.status == HealthStatus.HEALTHY
        assert result.message == "Test passed"
        assert result.details == {"key": "value"}
        assert result.response_time_ms == 10.5
        assert isinstance(result.timestamp, datetime)

    def test_result_to_dict(self):
        """Test converting result to dictionary"""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            message="Test passed",
            details={"key": "value"},
        )

        d = result.to_dict()
        assert d["name"] == "test_check"
        assert d["status"] == "healthy"
        assert d["message"] == "Test passed"
        assert d["details"] == {"key": "value"}
        assert "timestamp" in d


class TestHealthChecker:
    """Test HealthChecker class"""

    @pytest.fixture
    def checker(self):
        """Create a fresh HealthChecker"""
        reset_health_checker()
        return HealthChecker()

    @pytest.mark.asyncio
    async def test_run_all_checks_returns_system_health(self, checker):
        """Test that run_all_checks returns a SystemHealth object"""
        result = await checker.run_all_checks()

        assert isinstance(result, SystemHealth)
        assert isinstance(result.overall_status, HealthStatus)
        assert isinstance(result.checks, list)
        assert result.total_checks > 0

    @pytest.mark.asyncio
    async def test_default_checks_are_registered(self, checker):
        """Test that default checks are registered"""
        result = await checker.run_all_checks()

        check_names = [c.name for c in result.checks]
        assert "python_version" in check_names
        assert "filesystem" in check_names
        assert "environment" in check_names

    @pytest.mark.asyncio
    async def test_python_version_check_passes(self, checker):
        """Test Python version check passes on supported version"""
        result = await checker.run_check("python_version")

        assert result.name == "python_version"
        assert result.status == HealthStatus.HEALTHY
        assert "Python" in result.message

    @pytest.mark.asyncio
    async def test_filesystem_check_passes(self, checker):
        """Test filesystem check passes when writable"""
        result = await checker.run_check("filesystem")

        assert result.name == "filesystem"
        assert result.status == HealthStatus.HEALTHY
        assert result.details["write_access"] is True

    @pytest.mark.asyncio
    async def test_environment_check_passes(self, checker):
        """Test environment check passes with valid setup"""
        result = await checker.run_check("environment")

        assert result.name == "environment"
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]

    @pytest.mark.asyncio
    async def test_overall_status_healthy_when_all_pass(self, checker):
        """Test overall status is healthy when all checks pass"""
        result = await checker.run_all_checks()

        assert result.overall_status in [
            HealthStatus.HEALTHY,
            HealthStatus.DEGRADED,
        ]
        assert (
            result.healthy_count + result.degraded_count + result.unhealthy_count
            == result.total_checks
        )

    def test_register_custom_check(self, checker):
        """Test registering a custom health check"""

        def custom_check():
            return HealthCheckResult(
                name="custom",
                status=HealthStatus.HEALTHY,
                message="Custom check passed",
            )

        checker.register_check("custom", custom_check)

        # Check that it was registered by running all checks
        import asyncio

        result = asyncio.run(checker.run_all_checks())
        check_names = [c.name for c in result.checks]
        assert "custom" in check_names

    @pytest.mark.asyncio
    async def test_run_unregistered_check_raises_error(self, checker):
        """Test that running an unregistered check raises KeyError"""
        with pytest.raises(KeyError):
            await checker.run_check("nonexistent")


class TestSystemHealth:
    """Test SystemHealth dataclass"""

    def test_system_health_creation(self):
        """Test creating SystemHealth"""
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, "OK"),
            HealthCheckResult("check2", HealthStatus.HEALTHY, "OK"),
        ]

        health = SystemHealth(
            overall_status=HealthStatus.HEALTHY,
            checks=checks,
            total_checks=2,
            healthy_count=2,
            degraded_count=0,
            unhealthy_count=0,
        )

        assert health.overall_status == HealthStatus.HEALTHY
        assert len(health.checks) == 2
        assert health.total_checks == 2
        assert health.healthy_count == 2

    def test_system_health_to_dict(self):
        """Test converting SystemHealth to dict"""
        checks = [HealthCheckResult("check1", HealthStatus.HEALTHY, "OK")]

        health = SystemHealth(
            overall_status=HealthStatus.HEALTHY,
            checks=checks,
            total_checks=1,
            healthy_count=1,
            degraded_count=0,
            unhealthy_count=0,
        )

        d = health.to_dict()
        assert d["overall_status"] == "healthy"
        assert d["total_checks"] == 1
        assert d["healthy_count"] == 1
        assert len(d["checks"]) == 1


class TestDiagnostics:
    """Test Diagnostics class"""

    def test_diagnose_import_error_for_missing_module(self):
        """Test diagnosing import error for non-existent module"""
        result = Diagnostics.diagnose_import_error("nonexistent_module_xyz")

        assert result["module"] == "nonexistent_module_xyz"
        assert result["in_python_path"] is False
        assert result["file_exists"] is False
        assert len(result["suggestions"]) > 0

    def test_check_file_permissions_for_existing_file(self):
        """Test checking permissions for existing file"""
        # Use a file that definitely exists
        result = Diagnostics.check_file_permissions(__file__)

        assert result["path"] == __file__
        assert result["exists"] is True
        assert result["readable"] is True

    def test_check_file_permissions_for_nonexistent_file(self):
        """Test checking permissions for non-existent file"""
        result = Diagnostics.check_file_permissions("/nonexistent/path/file.txt")

        assert result["path"] == "/nonexistent/path/file.txt"
        assert result["exists"] is False
        assert result["readable"] is False

    def test_get_system_info(self):
        """Test getting system information"""
        info = Diagnostics.get_system_info()

        assert "python" in info
        assert "environment" in info
        assert "cwd" in info
        assert "timestamp" in info
        assert "version" in info["python"]


class TestGlobalHealthChecker:
    """Test global health checker instance functions"""

    def test_get_health_checker_returns_singleton(self):
        """Test that get_health_checker returns the same instance"""
        reset_health_checker()
        checker1 = get_health_checker()
        checker2 = get_health_checker()

        assert checker1 is checker2

    def test_reset_health_checker_creates_new_instance(self):
        """Test that reset creates a new instance"""
        reset_health_checker()
        checker1 = get_health_checker()
        reset_health_checker()
        checker2 = get_health_checker()

        assert checker1 is not checker2
