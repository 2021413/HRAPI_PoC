"""
Client HTTP bas niveau pour l'API hr-management-api.

Chaque méthode est une primitive utilisée par les modules d'exploitation.
Aucune logique de scénario ici : seulement des appels bruts.
"""

from __future__ import annotations
import requests


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.api = f"{self.base}/api/v1"
        self.s = requests.Session()
        self.s.headers["Content-Type"] = "application/json"

    @staticmethod
    def _json(r: requests.Response) -> dict:
        try:
            return r.json()
        except ValueError:
            return {}

    def _auth(self, token: str | None, extra: dict | None = None) -> dict:
        h = {}
        if token:
            h["Authorization"] = f"Bearer {token}"
        if extra:
            h.update(extra)
        return h

    # --- auth ---------------------------------------------------------------

    def forgot_password(self, email: str) -> dict:
        """HRAPI-2026-001 : la réponse contient `debugToken` (jeton en clair)."""
        r = self.s.post(f"{self.api}/auth/forgot-password", json={"email": email})
        return self._json(r).get("data", {})

    def reset_password(self, token: str, new_password: str) -> dict:
        r = self.s.post(
            f"{self.api}/auth/reset-password",
            json={"token": token, "password": new_password},
        )
        return self._json(r)

    def login(self, email: str, password: str) -> dict:
        r = self.s.post(f"{self.api}/auth/login", json={"email": email, "password": password})
        return self._json(r).get("data", {})

    def me(self, token: str) -> dict:
        r = self.s.get(f"{self.api}/auth/me", headers=self._auth(token))
        return self._json(r).get("data", {})

    # --- rôles --------------------------------------------------------------

    def set_system_role(self, token: str, user_id: str, role: str) -> dict:
        """HRAPI-2026-003 : role:manage suffit, pas de contrôle d'organisation."""
        r = self.s.put(
            f"{self.api}/roles/users/{user_id}/system-role",
            headers=self._auth(token),
            json={"systemRole": role},
        )
        return self._json(r)

    # --- données ------------------------------------------------------------

    def list_organizations(self, token: str) -> list:
        r = self.s.get(f"{self.api}/organizations?pageSize=100", headers=self._auth(token))
        return self._json(r).get("data", [])

    def list_employees(self, token: str, org_id: str | None = None) -> list:
        """HRAPI-2026-002 : X-Organization-Id prime sur le tenant du jeton."""
        extra = {"X-Organization-Id": org_id} if org_id else None
        r = self.s.get(f"{self.api}/employees?pageSize=100", headers=self._auth(token, extra))
        return self._json(r).get("data", [])

    def get_employee(self, token: str, emp_id: str) -> dict:
        """HRAPI-2026-004 : GET /employees/:id ne vérifie pas l'organisation (IDOR)."""
        r = self.s.get(f"{self.api}/employees/{emp_id}", headers=self._auth(token))
        return self._json(r).get("data", {})

    def salary_history(self, token: str, emp_id: str) -> dict:
        r = self.s.get(f"{self.api}/employees/{emp_id}/salary-history", headers=self._auth(token))
        return self._json(r)

    def add_org_admin(self, token: str, org_id: str, payload: dict) -> dict:
        """HRAPI-2026-005 : POST /organizations/:id/admins sans contrôle d'appartenance."""
        r = self.s.post(
            f"{self.api}/organizations/{org_id}/admins",
            headers=self._auth(token),
            json=payload,
        )
        return self._json(r)

    def import_from_url(self, token: str, payload: dict) -> dict:
        """HRAPI-2026-007 (SSRF) + HRAPI-2026-026 (path traversal via fileName)."""
        r = self.s.post(
            f"{self.api}/documents/import-from-url",
            headers=self._auth(token),
            json=payload,
        )
        return {"status": r.status_code, **self._json(r)}

    def download_document(self, token: str, doc_id: str) -> requests.Response:
        """HRAPI-2026-006 : route sans permission ni contrôle de tenant."""
        return self.s.get(f"{self.api}/documents/{doc_id}/download", headers=self._auth(token))
