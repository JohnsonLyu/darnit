"""Tests for darnit.core.discovery module."""

from unittest.mock import MagicMock

import pytest

from darnit.core import discovery
from darnit.core.discovery import (
    _resolve_distribution_name,
    clear_cache,
    discover_implementations,
    get_implementation,
)
from darnit.core.verification import VerificationResult


class _StubImplementation:
    """Minimal object satisfying the ComplianceImplementation protocol."""

    name = "stub-framework"
    display_name = "Stub Framework"
    version = "9.9.9"
    spec_version = "Stub v1"

    def get_all_controls(self):
        return []

    def get_controls_by_level(self, level):
        return []

    def get_rules_catalog(self):
        return {}

    def get_remediation_registry(self):
        return {}

    def get_framework_config_path(self):
        return None

    def register_controls(self):
        return None


def _fake_entry_point(name: str, dist_name: str | None) -> MagicMock:
    """Build an entry-point double for the ``darnit.implementations`` group.

    ``dist_name=None`` models an entry point with no distribution metadata.
    """
    ep = MagicMock()
    ep.name = name
    ep.load.return_value = _StubImplementation
    if dist_name is None:
        # MagicMock would otherwise autocreate a truthy `dist`.
        ep.dist = None
    else:
        dist = MagicMock()
        dist.name = dist_name
        ep.dist = dist
    return ep


@pytest.fixture
def fake_entry_points(monkeypatch):
    """Install fake entry points for the ``darnit.implementations`` group.

    ``discovery`` imports ``entry_points`` inside the function, so the patch
    must land on ``importlib.metadata``.
    """

    def _install(*eps):
        def _entry_points(group=None, **kwargs):
            return list(eps) if group == "darnit.implementations" else []

        monkeypatch.setattr("importlib.metadata.entry_points", _entry_points)

    return _install


@pytest.fixture
def verified_package_names(monkeypatch):
    """Record names passed to the verifier, without network or cache access."""
    recorded: list[str] = []

    class _RecordingVerifier:
        def __init__(self, config):
            self.config = config

        def verify_plugin(self, package_name, use_cache=True):
            recorded.append(package_name)
            return VerificationResult(verified=True, signed=True, trusted=True)

    monkeypatch.setattr(discovery, "PluginVerifier", _RecordingVerifier)
    return recorded


class TestDiscoverImplementations:
    """Tests for discover_implementations function."""

    @pytest.fixture(autouse=True)
    def clear_discovery_cache(self):
        """Clear cache before each test."""
        clear_cache()
        yield
        clear_cache()

    @pytest.mark.unit
    def test_discovers_openssf_baseline(self):
        """Test that openssf-baseline implementation is discovered."""
        implementations = discover_implementations()
        assert "openssf-baseline" in implementations

    @pytest.mark.unit
    def test_clear_cache_works(self):
        """Test that clear_cache resets the cache."""
        impl1 = discover_implementations()
        clear_cache()
        impl2 = discover_implementations()
        # Should be different dict objects after cache clear
        assert impl1 is not impl2


class TestGetImplementation:
    """Tests for get_implementation function."""

    @pytest.fixture(autouse=True)
    def clear_discovery_cache(self):
        """Clear cache before each test."""
        clear_cache()
        yield
        clear_cache()

    @pytest.mark.unit
    def test_get_existing_implementation(self):
        """Test getting an existing implementation by name."""
        impl = get_implementation("openssf-baseline")
        assert impl is not None
        assert impl.name == "openssf-baseline"

    @pytest.mark.unit
    def test_get_nonexistent_implementation(self):
        """Test getting a nonexistent implementation returns None."""
        impl = get_implementation("nonexistent-implementation")
        assert impl is None


class TestDistributionNameResolution:
    """Tests that verification receives the distribution name, not the slug."""

    @pytest.fixture(autouse=True)
    def clear_discovery_cache(self):
        """Clear cache before each test."""
        clear_cache()
        yield
        clear_cache()

    @pytest.mark.unit
    def test_resolves_to_distribution_name(self):
        """``ep.dist.name`` wins over the entry-point slug."""
        ep = _fake_entry_point("openssf-baseline", dist_name="darnit-baseline")
        assert _resolve_distribution_name(ep) == "darnit-baseline"

    @pytest.mark.unit
    def test_falls_back_when_dist_is_none(self):
        """Falls back to the slug when ``ep.dist`` is None."""
        ep = _fake_entry_point("reproducibility", dist_name=None)
        assert _resolve_distribution_name(ep) == "reproducibility"

    @pytest.mark.unit
    def test_falls_back_when_dist_name_is_blank(self):
        """An empty distribution name is treated as absent."""
        ep = _fake_entry_point("gittuf", dist_name="")
        assert _resolve_distribution_name(ep) == "gittuf"

    @pytest.mark.unit
    def test_verifier_receives_distribution_name(
        self, fake_entry_points, verified_package_names
    ):
        """Discovery verifies the distribution, not the entry-point slug."""
        fake_entry_points(
            _fake_entry_point("openssf-baseline", dist_name="darnit-baseline")
        )

        discover_implementations()

        assert verified_package_names == ["darnit-baseline"]

    @pytest.mark.unit
    def test_verifier_receives_slug_when_dist_is_none(
        self, fake_entry_points, verified_package_names
    ):
        """The fallback reaches the verifier and discovery still loads the plugin."""
        fake_entry_points(_fake_entry_point("hello", dist_name=None))

        implementations = discover_implementations()

        assert verified_package_names == ["hello"]
        assert "stub-framework" in implementations
