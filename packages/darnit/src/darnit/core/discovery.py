"""Plugin discovery for darnit compliance implementations.

This module discovers installed compliance implementations via Python entry points.
Implementations register under the 'darnit.implementations' group.
"""


from typing import TYPE_CHECKING, NamedTuple

from darnit.core.verification import PluginVerifier, VerificationConfig

from .logging import get_logger
from .plugin import ComplianceImplementation

if TYPE_CHECKING:
    from importlib.metadata import EntryPoint

    from darnit.config.operator.schema import PluginSettings

logger = get_logger("core.discovery")


class _PolicyKey(NamedTuple):
    """The verification inputs that can change whether a plugin is accepted.

    Derived from the effective ``VerificationConfig``, never from
    ``PluginSettings`` directly: ``PluginSettings()`` and
    ``PluginSettings(allow_unsigned=False)`` hold the same field value, but
    only the second concludes the policy (``model_fields_set``), so they must
    not be treated as the same policy.

    ``cache_dir`` and ``cache_ttl`` are deliberately absent -- they decide
    where a verification result is memoized, not whether a plugin is accepted.
    """

    allow_unsigned: bool
    trusted_publishers: tuple[str, ...]
    verify_online: bool


def _policy_key(config: VerificationConfig) -> _PolicyKey:
    """Reduce a verification config to the inputs that affect acceptance."""
    return _PolicyKey(
        allow_unsigned=config.allow_unsigned,
        # Already folds in use_default_publishers.
        trusted_publishers=tuple(config.get_all_trusted_publishers()),
        verify_online=config.verify_online,
    )


# Cache for discovered implementations, plus the policy they were verified
# under. Both are process-global, so a caller that supplies no operator policy
# must not leave a permissive cache behind for a later strict audit to reuse.
_implementations: dict[str, ComplianceImplementation] | None = None
_cache_policy: _PolicyKey | None = None


def _resolve_distribution_name(ep: "EntryPoint") -> str:
    """Return the installed distribution name backing an entry point.

    Verification looks plugins up by distribution name (``darnit-baseline``),
    not by the entry-point slug (``openssf-baseline``). Entry points built by
    hand have no ``dist``, so fall back to the slug.
    """
    dist = getattr(ep, "dist", None)
    dist_name = getattr(dist, "name", None) if dist is not None else None
    if dist_name:
        return dist_name

    logger.debug(
        "Entry point '%s' carries no distribution metadata; verifying under "
        "the entry-point name instead.",
        ep.name,
    )
    return ep.name


def discover_implementations(
    plugins: "PluginSettings | None" = None,
) -> dict[str, ComplianceImplementation]:
    """Discover compliance implementations from entry points.

    Args:
        plugins: The operator's ``[plugins]`` settings, taken from an operator
            configuration that has already passed the feature-040 containment
            check for the audit target. None keeps this module's existing
            default policy. The audited repository is never a source for this.

    Returns:
        Mapping of implementation name to instance.
    """
    global _implementations, _cache_policy

    verification_config = VerificationConfig.from_plugin_settings(plugins)
    policy = _policy_key(verification_config)

    if _implementations is not None and _cache_policy == policy:
        return _implementations

    if _implementations is not None:
        logger.debug(
            "Plugin verification policy changed; re-verifying %d implementation(s).",
            len(_implementations),
        )

    # Assigned before the loop so that a plugin whose register() re-enters
    # discovery sees the partial result rather than recursing.
    _implementations = {}
    _cache_policy = policy

    # Use importlib.metadata for Python 3.9+
    from importlib.metadata import entry_points

    eps = entry_points(group="darnit.implementations")

    verifier = PluginVerifier(verification_config)

    for ep in eps:
        try:
            dist_name = _resolve_distribution_name(ep)

            try:
                verification_result = verifier.verify_plugin(dist_name)
            except Exception as e:
                logger.warning(
                    f"Plugin verification errored for '{ep.name}', loading anyway because "
                    f"allow_unsigned=True: {e}"
                )
                verification_result = None

            if verification_result is not None and not verification_result.verified:
                message = verification_result.error or verification_result.warning or "unknown verification failure"

                if verification_config.allow_unsigned:
                    logger.warning(
                        f"Plugin '{ep.name}' failed verification but will be loaded anyway: "
                        f"{message}"
                    )
                else:
                    logger.warning(
                        f"Skipping plugin '{ep.name}' because verification failed: "
                        f"{message}"
                    )
                    continue

            # Load the entry point (calls the register() function)
            register_func = ep.load()
            impl = register_func()

            if isinstance(impl, ComplianceImplementation):
                _implementations[impl.name] = impl
                logger.info(f"Discovered implementation: {impl.name} v{impl.version}")
            else:
                logger.warning(
                    f"Entry point {ep.name} returned {type(impl)}, "
                    f"expected ComplianceImplementation"
                )

        except (ImportError, AttributeError, TypeError) as e:
            logger.error(f"Failed to load implementation {ep.name}: {e}")
            continue
        except Exception as e:
            logger.error(f"Error occurred while verifying or loading plugin '{ep.name}': {e}")
            continue

    logger.info(f"Discovered {len(_implementations)} implementation(s)")
    return _implementations


def get_implementation(
    name: str, plugins: "PluginSettings | None" = None
) -> ComplianceImplementation | None:
    """Get a specific implementation by name.

    Args:
        name: Implementation name (e.g., 'openssf-baseline')
        plugins: Operator ``[plugins]`` settings to verify under. See
            ``discover_implementations``.

    Returns:
        Implementation instance or None if not found.
    """
    implementations = discover_implementations(plugins)
    return implementations.get(name)


def register_implementation_handlers(
    framework_name: str | None, plugins: "PluginSettings | None" = None
) -> bool:
    """Register a framework implementation's custom sieve handlers.

    Plugin packages that ship Python sieve handlers (as opposed to controls
    built only from the built-in handlers) expose them through
    ``register_handlers()``. Until that runs, TOML controls referencing a
    plugin handler by short name resolve to nothing and the orchestrator
    falls through to `manual`, producing a WARN that looks like "we could
    not verify" rather than "this handler was never loaded" (issue #427).

    Idempotent: the underlying registry overwrites by name, and
    implementations are cached, so repeat calls are cheap and safe.

    Args:
        framework_name: Implementation name (e.g. ``"reproducibility"``).
            ``None`` is accepted and is a no-op, so callers that may not
            have resolved a framework do not need to guard.
        plugins: Operator ``[plugins]`` settings to verify under. See
            ``discover_implementations``.

    Returns:
        True if handlers were registered, False if there was nothing to do
        (no framework name, no such implementation, or the implementation
        does not expose ``register_handlers``).
    """
    if not framework_name:
        return False

    impl = get_implementation(framework_name, plugins)
    if impl is None:
        logger.debug("No implementation found for '%s'", framework_name)
        return False

    # Two method names are in use across in-tree plugins:
    #   register_handlers       -- documented in CLAUDE.md; darnit-baseline
    #   register_sieve_handlers -- darnit-gittuf, darnit-reproducibility
    # Those two work today only because their `register()` entry point calls
    # register_sieve_handlers() during discovery. That is a side channel, not
    # the protocol: discovery results are cached, so any caller that warmed
    # the cache earlier in the process leaves the handlers unregistered and
    # every plugin control silently falls through to `manual`. Accepting both
    # names here makes registration explicit and cache-independent.
    # hasattr per Constitution Principle I: missing methods degrade, never crash.
    method = None
    for name in ("register_handlers", "register_sieve_handlers"):
        if hasattr(impl, name):
            method = getattr(impl, name)
            break
    if method is None:
        return False

    try:
        method()
    except Exception as err:  # noqa: BLE001 - a bad plugin must not kill the audit
        logger.warning(
            "Failed to register handlers for '%s': %s: %s",
            framework_name,
            type(err).__name__,
            err,
        )
        return False

    logger.debug("Registered handlers for '%s'", framework_name)
    return True


def clear_cache() -> None:
    """Clear the implementation cache and the policy it was built under.

    Useful for testing or when implementations may have changed.
    """
    global _implementations, _cache_policy
    _implementations = None
    _cache_policy = None


__all__ = [
    "clear_cache",
    "discover_implementations",
    "get_implementation",
    "register_implementation_handlers",
]
