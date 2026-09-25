"""Profile registry: ``(.vmx mapping, HostInfo, ProfileOptions) -> ProfileResult``.

Submodules are imported *lazily* inside :func:`build_all` so that:

* every profile can be unit-tested in isolation (``import macopt.profiles.topology``
  does not drag in the others), and
* a half-finished module fails loudly at call time instead of at import time.

Dependency direction (enforced by tests): ``profiles.*`` may import the
contract layer (``model``, ``vmxfile``, ``errors``) and ``macopt.guestos`` /
``macopt.keys``, but never ``cli``, ``writer``, ``backup`` or ``verify``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from importlib import import_module

from ..model import HostInfo, ProfileOptions, ProfileResult

Builder = Callable[[Mapping[str, str], HostInfo, ProfileOptions], ProfileResult]

# Modules that contribute .vmx writes (schedule is host-side and excluded).
APPLY_MODULES: tuple[str, ...] = (
    "guestos",
    "topology",
    "timing",
    "gfxnet",
    "identity",
    "cpuid",
)

_BUILDERS: dict[str, tuple[str, str]] = {
    "guestos": ("macopt.guestos", "build"),
    "topology": ("macopt.profiles.topology", "build"),
    "timing": ("macopt.profiles.timing", "build"),
    "gfxnet": ("macopt.profiles.gfxnet", "build"),
    "identity": ("macopt.profiles.identity", "build"),
    "cpuid": ("macopt.profiles.cpuid", "build"),
}


def get_builder(module: str) -> Builder:
    """Import and return one profile's ``build`` callable."""
    if module not in _BUILDERS:
        raise KeyError(f"unknown profile module: {module!r} (known: {sorted(_BUILDERS)})")
    mod_name, attr = _BUILDERS[module]
    mod = import_module(mod_name)
    builder = getattr(mod, attr, None)
    if builder is None:
        raise AttributeError(f"{mod_name} does not define {attr}()")
    return builder  # type: ignore[return-value]


def build_all(
    mapping: Mapping[str, str],
    host: HostInfo,
    opts: ProfileOptions,
    *,
    modules: tuple[str, ...] | None = None,
) -> ProfileResult:
    """Run every requested module and merge the results.

    Order is stable (the tuple order above) so plans diff deterministically
    across runs and platforms.
    """
    wanted = modules if modules is not None else opts.modules
    result = ProfileResult()
    for module in APPLY_MODULES:
        if module not in wanted:
            continue
        result = result.merged(get_builder(module)(mapping, host, opts))
    return result
