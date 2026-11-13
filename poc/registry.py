"""Découverte et enregistrement des modules d'exploitation."""

from __future__ import annotations
import importlib
import pkgutil

from . import modules as modules_pkg
from .modules.base import Module


def load_modules() -> dict[str, Module]:
    """Instancie chaque module exposant une classe `Exploit`. Clé = id (HRAPI-...)."""
    found: dict[str, Module] = {}
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        if info.name in ("base",):
            continue
        mod = importlib.import_module(f"{modules_pkg.__name__}.{info.name}")
        cls = getattr(mod, "Exploit", None)
        if cls is None:
            continue
        inst = cls()
        found[inst.id] = inst
    return dict(sorted(found.items(), key=lambda kv: kv[0]))
