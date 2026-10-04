"""Tests for darnit.core.discovery module."""

from unittest.mock import MagicMock

import pytest

from darnit.config.operator.schema import PluginSettings
from darnit.core import discovery
from darnit.core.discovery import (
    _policy_key,
    _resolve_distribution_name,
    clear_cache,
    discover_implementations,
    get_implementation,
)
from darnit.core.verification import (
    DEFAULT_TRUSTED_PUBLISHERS,
    VerificationConfig,
    VerificationResult,
)


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


def _key(plugins: PluginSettings | None):
    """The effective cache key of operator ``[plugins]`` settings."""
    return _policy_key(VerificationConfig.from_plugin_settings(plugins))


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


@pytest.fixture
def verifier_spy(monkeypatch):
    """Record the verification config of every discovery run.

    Discovery constructs one ``PluginVerifier`` per rebuild, so the number of
    recorded configs is also the number of times discovery re-verified rather
    than answering from its cache.
    """

    class _Spy:
        def __init__(self):
            self.configs: list[VerificationConfig] = []
            self.verified = True

        @property
        def runs(self) -> int:
            return len(self.configs)

        @property
        def last(self) -> VerificationConfig:
            return self.configs[-1]

    spy = _Spy()

    class _RecordingVerifier:
        def __init__(self, config):
            spy.configs.append(config)

        def verify_plugin(self, package_name, use_cache=True):
            return VerificationResult(
                verified=spy.verified,
                signed=spy.verified,
                trusted=spy.verified,
                error=None if spy.verified else "no Sigstore attestation",
            )

    monkeypatch.setattr(discovery, "PluginVerifier", _RecordingVerifier)
    return spy


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
    def test_missing_dist_returns_none(self):
        """No distribution metadata does not fall back to the entry-point slug."""
        ep = _fake_entry_point("reproducibility", dist_name=None)
        assert _resolve_distribution_name(ep) is None
        assert _resolve_distribution_name(ep) != ep.name

    @pytest.mark.unit
    def test_blank_dist_name_returns_none(self):
        """A blank or non-string distribution name is not an identity."""
        ep = _fake_entry_point("gittuf", dist_name="")
        assert _resolve_distribution_name(ep) is None

        ep.dist.name = None
        assert _resolve_distribution_name(ep) is None
        ep.dist.name = "   "
        assert _resolve_distribution_name(ep) is None

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
    def test_unresolved_distribution_is_skipped(self, fake_entry_points, verified_package_names):
        """Missing distribution identity skips the entry point before verification."""
        ep = _fake_entry_point("hello", dist_name=None)
        fake_entry_points(ep)

        implementations = discover_implementations()

        assert verified_package_names == []
        assert "hello" not in verified_package_names
        ep.load.assert_not_called()
        assert "stub-framework" not in implementations


class TestPolicyKey:
    """The cache key is derived from the effective verification policy."""

    @pytest.mark.unit
    def test_unset_differs_from_explicit_false(self):
        """``PluginSettings()`` and ``PluginSettings(allow_unsigned=False)``.

        Both hold ``allow_unsigned=False`` as a field value, but only the
        second concludes the policy, so they must not share a cache entry.
        """
        unset = PluginSettings()
        explicit = PluginSettings(allow_unsigned=False)

        assert unset.allow_unsigned == explicit.allow_unsigned
        assert _key(unset) != _key(explicit)

    @pytest.mark.unit
    def test_unset_matches_no_settings_at_all(self):
        """An operator config without a ``[plugins]`` table changes nothing."""
        assert _key(PluginSettings()) == _key(None)

    @pytest.mark.unit
    def test_key_includes_effective_publishers(self):
        """The key holds the publisher list after defaults are folded in."""
        key = _key(PluginSettings(trusted_publishers=["https://github.com/my-org"]))

        assert "https://github.com/my-org" in key.trusted_publishers
        assert set(DEFAULT_TRUSTED_PUBLISHERS) <= set(key.trusted_publishers)
        assert key != _key(PluginSettings(trusted_publishers=["https://github.com/other-org"]))

    @pytest.mark.unit
    def test_default_publishers_toggle_changes_the_key(self):
        """``use_default_publishers`` reaches the key through the folded list."""
        with_defaults = _policy_key(VerificationConfig())
        without_defaults = _policy_key(VerificationConfig(use_default_publishers=False))

        assert with_defaults != without_defaults

    @pytest.mark.unit
    def test_online_verification_is_part_of_the_key(self):
        """``verify_online`` decides whether an attestation is ever fetched."""
        assert _policy_key(VerificationConfig()) != _policy_key(
            VerificationConfig(verify_online=False)
        )

    @pytest.mark.unit
    def test_cache_location_is_not_part_of_the_key(self, tmp_path):
        """Where a result is memoized cannot change whether a plugin is accepted."""
        assert _policy_key(VerificationConfig(cache_dir=tmp_path)) == _policy_key(
            VerificationConfig(cache_dir=tmp_path / "elsewhere")
        )


class TestOperatorPolicyReachesVerification:
    """Operator ``[plugins]`` settings decide the verification policy."""

    @pytest.fixture(autouse=True)
    def clear_discovery_cache(self):
        clear_cache()
        yield
        clear_cache()

    @pytest.fixture(autouse=True)
    def one_plugin(self, fake_entry_points):
        fake_entry_points(_fake_entry_point("openssf-baseline", dist_name="darnit-baseline"))

    @pytest.mark.unit
    def test_no_settings_keeps_the_permissive_default(self, verifier_spy):
        """Path A: #448 does not change the default, only where policy comes from."""
        discover_implementations()

        assert verifier_spy.last.allow_unsigned is True

    @pytest.mark.unit
    def test_unset_allow_unsigned_keeps_the_permissive_default(self, verifier_spy):
        discover_implementations(PluginSettings())

        assert verifier_spy.last.allow_unsigned is True

    @pytest.mark.unit
    def test_explicit_allow_unsigned_false_is_strict(self, verifier_spy):
        discover_implementations(PluginSettings(allow_unsigned=False))

        assert verifier_spy.last.allow_unsigned is False

    @pytest.mark.unit
    def test_explicit_allow_unsigned_true_is_honored(self, verifier_spy):
        discover_implementations(PluginSettings(allow_unsigned=True))

        assert verifier_spy.last.allow_unsigned is True

    @pytest.mark.unit
    def test_trusted_publishers_reach_verification(self, verifier_spy):
        discover_implementations(
            PluginSettings(trusted_publishers=["https://github.com/my-org"])
        )

        publishers = verifier_spy.last.get_all_trusted_publishers()
        assert "https://github.com/my-org" in publishers
        assert set(DEFAULT_TRUSTED_PUBLISHERS) <= set(publishers)

    @pytest.mark.unit
    def test_strict_policy_skips_an_unverified_plugin(self, verifier_spy):
        """The policy reaches the accept decision, not just the verifier."""
        verifier_spy.verified = False

        implementations = discover_implementations(PluginSettings(allow_unsigned=False))

        assert implementations == {}

    @pytest.mark.unit
    def test_permissive_policy_loads_an_unverified_plugin(self, verifier_spy):
        """Control for the test above: the same plugin loads under the default."""
        verifier_spy.verified = False

        implementations = discover_implementations(PluginSettings(allow_unsigned=True))

        assert "stub-framework" in implementations

    @pytest.mark.unit
    def test_get_implementation_forwards_the_policy(self, verifier_spy):
        get_implementation("stub-framework", PluginSettings(allow_unsigned=False))

        assert verifier_spy.last.allow_unsigned is False

    @pytest.mark.unit
    def test_register_implementation_handlers_forwards_the_policy(self, verifier_spy):
        discovery.register_implementation_handlers(
            "stub-framework", PluginSettings(allow_unsigned=False)
        )

        assert verifier_spy.last.allow_unsigned is False


class TestPolicyAwareCache:
    """The process-global cache is only reused under the same effective policy."""

    @pytest.fixture(autouse=True)
    def clear_discovery_cache(self):
        clear_cache()
        yield
        clear_cache()

    @pytest.fixture(autouse=True)
    def one_plugin(self, fake_entry_points):
        fake_entry_points(_fake_entry_point("openssf-baseline", dist_name="darnit-baseline"))

    @pytest.mark.unit
    def test_same_policy_reuses_the_cache(self, verifier_spy):
        """Equivalent-but-distinct settings objects are the same policy."""
        first = discover_implementations(PluginSettings(allow_unsigned=False))
        second = discover_implementations(PluginSettings(allow_unsigned=False))

        assert verifier_spy.runs == 1
        assert first is second

    @pytest.mark.unit
    def test_strict_policy_rebuilds_a_permissive_cache(self, verifier_spy):
        """A no-policy caller must not warm a permissive cache for a later audit."""
        permissive = discover_implementations()
        strict = discover_implementations(PluginSettings(allow_unsigned=False))

        assert verifier_spy.runs == 2
        assert [c.allow_unsigned for c in verifier_spy.configs] == [True, False]
        assert permissive is not strict

    @pytest.mark.unit
    def test_permissive_policy_is_not_served_from_a_strict_cache(self, verifier_spy):
        strict = discover_implementations(PluginSettings(allow_unsigned=False))
        permissive = discover_implementations(PluginSettings(allow_unsigned=True))

        assert verifier_spy.runs == 2
        assert [c.allow_unsigned for c in verifier_spy.configs] == [False, True]
        assert strict is not permissive

    @pytest.mark.unit
    def test_unset_cache_is_rebuilt_for_an_explicit_strict_policy(self, verifier_spy):
        """The unset/explicit-false distinction survives into the cache guard."""
        discover_implementations(PluginSettings())
        discover_implementations(PluginSettings(allow_unsigned=False))

        assert verifier_spy.runs == 2
        assert [c.allow_unsigned for c in verifier_spy.configs] == [True, False]

    @pytest.mark.unit
    def test_an_added_publisher_rebuilds_the_cache(self, verifier_spy):
        discover_implementations(PluginSettings(allow_unsigned=False))
        discover_implementations(
            PluginSettings(allow_unsigned=False, trusted_publishers=["https://github.com/my-org"])
        )

        assert verifier_spy.runs == 2

    @pytest.mark.unit
    def test_clear_cache_resets_the_policy_guard(self, verifier_spy):
        discover_implementations(PluginSettings(allow_unsigned=False))
        assert discovery._cache_policy is not None

        clear_cache()

        assert discovery._implementations is None
        assert discovery._cache_policy is None

        discover_implementations(PluginSettings(allow_unsigned=False))
        assert verifier_spy.runs == 2
