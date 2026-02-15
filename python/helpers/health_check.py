"""Health check and diagnostics system for Agent Zero.

Provides system status monitoring, configuration validation, and self-diagnostic
capabilities to help users troubleshoot issues and ensure system health.
"""

import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class HealthStatus(Enum):
    """Health check status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check."""

    name: str
    status: HealthStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "response_time_ms": self.response_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class SystemHealth:
    """Overall system health status."""

    overall_status: HealthStatus
    checks: list[HealthCheckResult]
    total_checks: int
    healthy_count: int
    degraded_count: int
    unhealthy_count: int
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_status": self.overall_status.value,
            "checks": [c.to_dict() for c in self.checks],
            "total_checks": self.total_checks,
            "healthy_count": self.healthy_count,
            "degraded_count": self.degraded_count,
            "unhealthy_count": self.unhealthy_count,
            "timestamp": self.timestamp.isoformat(),
        }


class HealthChecker:
    """System health checker with pluggable checks."""

    def __init__(self):
        """Initialize health checker."""
        self._checks: dict[str, Callable[[], HealthCheckResult]] = {}
        self._register_default_checks()

    def _register_default_checks(self) -> None:
        """Register default health checks."""
        self.register_check("python_version", self._check_python_version)
        self.register_check("filesystem", self._check_filesystem)
        self.register_check("environment", self._check_environment)

    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        """Register a health check function.

        Args:
            name: Unique name for the check
            check_func: Function that returns HealthCheckResult
        """
        self._checks[name] = check_func

    async def run_check(self, name: str) -> HealthCheckResult:
        """Run a single health check.

        Args:
            name: Name of the registered check

        Returns:
            HealthCheckResult with status and details

        Raises:
            KeyError: If check name not registered
        """
        if name not in self._checks:
            raise KeyError(f"Health check '{name}' not registered")

        start_time = time.time()
        try:
            result = self._checks[name]()
            result.response_time_ms = (time.time() - start_time) * 1000
            return result
        except Exception as e:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed with exception: {e!s}",
                response_time_ms=(time.time() - start_time) * 1000,
            )

    async def run_all_checks(self) -> SystemHealth:
        """Run all registered health checks.

        Returns:
            SystemHealth with overall status and all check results
        """
        checks = []

        for name in self._checks:
            try:
                result = await self.run_check(name)
                checks.append(result)
            except Exception as e:
                checks.append(
                    HealthCheckResult(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Failed to run check: {e!s}",
                    )
                )

        healthy_count = sum(1 for c in checks if c.status == HealthStatus.HEALTHY)
        degraded_count = sum(1 for c in checks if c.status == HealthStatus.DEGRADED)
        unhealthy_count = sum(1 for c in checks if c.status == HealthStatus.UNHEALTHY)

        # Determine overall status
        if unhealthy_count > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

        return SystemHealth(
            overall_status=overall_status,
            checks=checks,
            total_checks=len(checks),
            healthy_count=healthy_count,
            degraded_count=degraded_count,
            unhealthy_count=unhealthy_count,
        )

    def _check_python_version(self) -> HealthCheckResult:
        """Check Python version compatibility."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if version.major < 3 or (version.major == 3 and version.minor < 10):
            return HealthCheckResult(
                name="python_version",
                status=HealthStatus.UNHEALTHY,
                message=f"Python {version_str} is not supported. Requires Python 3.10+",
                details={"version": version_str, "required": ">=3.10"},
            )

        return HealthCheckResult(
            name="python_version",
            status=HealthStatus.HEALTHY,
            message=f"Python {version_str} is supported",
            details={"version": version_str},
        )

    def _check_filesystem(self) -> HealthCheckResult:
        """Check filesystem permissions and space."""
        try:
            # Check write access to current directory
            test_file = ".health_check_test"
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)

            return HealthCheckResult(
                name="filesystem",
                status=HealthStatus.HEALTHY,
                message="Filesystem is writable",
                details={"write_access": True},
            )
        except Exception as e:
            return HealthCheckResult(
                name="filesystem",
                status=HealthStatus.UNHEALTHY,
                message=f"Filesystem check failed: {e!s}",
                details={"write_access": False, "error": str(e)},
            )

    def _check_environment(self) -> HealthCheckResult:
        """Check environment variables and basic setup."""
        issues = []

        # Check for required environment variables
        if not os.environ.get("PATH"):
            issues.append("PATH environment variable not set")

        # Check Python path
        if not sys.path:
            issues.append("Python path is empty")

        if issues:
            return HealthCheckResult(
                name="environment",
                status=HealthStatus.DEGRADED,
                message=f"Environment issues found: {'; '.join(issues)}",
                details={"issues": issues},
            )

        return HealthCheckResult(
            name="environment",
            status=HealthStatus.HEALTHY,
            message="Environment is properly configured",
            details={"python_path_count": len(sys.path)},
        )


class Diagnostics:
    """Self-diagnostics for common issues."""

    @staticmethod
    def diagnose_import_error(module_name: str) -> dict[str, Any]:
        """Diagnose why a module import might be failing.

        Args:
            module_name: Name of the module that failed to import

        Returns:
            Dictionary with diagnosis and suggestions
        """
        diagnosis = {
            "module": module_name,
            "in_python_path": False,
            "file_exists": False,
            "suggestions": [],
        }

        # Check if module could be in Python path
        for path in sys.path:
            potential_path = os.path.join(path, module_name.replace(".", os.sep))
            if os.path.exists(potential_path) or os.path.exists(potential_path + ".py"):
                diagnosis["in_python_path"] = True
                diagnosis["file_exists"] = True
                break

        # Generate suggestions
        if not diagnosis["in_python_path"]:
            diagnosis["suggestions"].append(
                f"Module '{module_name}' not found in Python path. "
                "Check if it's installed or if PYTHONPATH is set correctly."
            )

        if not diagnosis["file_exists"] and diagnosis["in_python_path"]:
            diagnosis["suggestions"].append(
                "Module path exists but file not found. "
                "The module may be a namespace package or there's a naming issue."
            )

        return diagnosis

    @staticmethod
    def check_file_permissions(path: str) -> dict[str, Any]:
        """Check file permissions and accessibility.

        Args:
            path: Path to check

        Returns:
            Dictionary with permission status
        """
        result = {
            "path": path,
            "exists": False,
            "readable": False,
            "writable": False,
            "executable": False,
        }

        if os.path.exists(path):
            result["exists"] = True
            result["readable"] = os.access(path, os.R_OK)
            result["writable"] = os.access(path, os.W_OK)
            result["executable"] = os.access(path, os.X_OK)

        return result

    @staticmethod
    def get_system_info() -> dict[str, Any]:
        """Get comprehensive system information.

        Returns:
            Dictionary with system details
        """
        return {
            "python": {
                "version": sys.version,
                "executable": sys.executable,
                "platform": sys.platform,
                "path": sys.path[:5],  # First 5 entries only
            },
            "environment": {
                "variables": {
                    k: v
                    for k, v in os.environ.items()
                    if k.lower() not in ["key", "token", "secret", "password", "api_key"]
                }
            },
            "cwd": os.getcwd(),
            "timestamp": datetime.now().isoformat(),
        }


# Global health checker instance
_health_checker: HealthChecker | None = None


def get_health_checker() -> HealthChecker:
    """Get or create global health checker instance.

    Returns:
        HealthChecker singleton instance
    """
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def reset_health_checker() -> None:
    """Reset the global health checker (useful for testing)."""
    global _health_checker
    _health_checker = None
