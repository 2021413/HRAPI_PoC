"""
Socle commun à tous les modules d'exploitation.

Un module déclare :
  - des métadonnées (id, nom, cwe, cvss, description) ;
  - des OPTIONS (nom -> (obligatoire, défaut, aide)) ;
  - une méthode run(ctx) qui réalise l'attaque.

Le contexte (ctx) donne accès :
  - au client HTTP partagé (ctx.client) ;
  - au datastore global partagé entre modules (ctx.store) ;
  - aux fonctions d'affichage (ctx.ok / ctx.info / ctx.fail / ctx.line).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Option:
    required: bool = False
    default: str | None = None
    help: str = ""


@dataclass
class Context:
    client: object
    store: dict
    ok: Callable[[str], None]
    info: Callable[[str], None]
    fail: Callable[[str], None]
    line: Callable[[str], None]


class Module:
    id: str = ""
    name: str = ""
    cwe: str = ""
    cvss: str = ""
    description: str = ""
    options: dict[str, Option] = field(default_factory=dict)

    def __init__(self):
        # Valeurs saisies par l'utilisateur, par-dessus les défauts.
        self.values: dict[str, str] = {}

    # --- gestion des options ------------------------------------------------

    def opt(self, store: dict, key: str) -> str | None:
        """Résolution d'une option : saisie module > datastore global > défaut."""
        if key in self.values:
            return self.values[key]
        if key.upper() in store:
            return store[key.upper()]
        spec = self.options.get(key)
        return spec.default if spec else None

    def missing(self, store: dict) -> list[str]:
        return [
            k for k, spec in self.options.items()
            if spec.required and not self.opt(store, k)
        ]

    # --- à implémenter ------------------------------------------------------

    def run(self, ctx: Context) -> bool:
        raise NotImplementedError
