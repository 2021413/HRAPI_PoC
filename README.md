# HRAPI_PoC

Preuves de concept et rapport de vulnérabilités pour l'audit de l'API
`hr-management-api` (service RH multi-tenant Express + Prisma + PostgreSQL + Redis).

Le dépôt contient :

- une **console d'exploitation modulaire** (`poc/`), façon metasploit, avec un
  module par faille critique ;
- le **rapport de vulnérabilités** au format type registre CVE
  (`RAPPORT_VULNERABILITES.md`).

> ⚠️ **Usage autorisé uniquement.** Ces outils ne doivent être employés que
> contre une instance dont on possède l'autorisation explicite (ici, une
> instance de test locale avec des données de seed fictives). Toute utilisation
> hors de ce cadre est interdite.

## Prérequis

- Python 3.10+
- `pip install -r requirements.txt`
- une instance de `hr-management-api` accessible (par défaut `http://localhost:4000`)

## Lancer la console

```bash
python3 hrapi.py
# ou, depuis n'importe quel dossier :
python3 /chemin/vers/HRAPI_PoC/hrapi.py
```

Vous devez voir l'invite `hrapi > ` (et non le REPL Python `>>>`).

### Commandes

| Commande | Effet |
|---|---|
| `show modules` | liste les modules |
| `search <texte>` | filtre les modules |
| `use <id\|index\|nom>` | sélectionne un module |
| `info` | détail du module courant |
| `options` | options + datastore global |
| `set <clef> <valeur>` | règle une option, ou une variable globale (ex. `set email a@b`) |
| `unset <clef>` | efface une option |
| `run` / `exploit` | lance le module courant |
| `sessions` | état capturé (token, rôle, organisations) |
| `back` | désélectionne le module |
| `exit` / `quit` | quitter |

### Exemple : chaîne d'escalade

```text
hrapi > set email lena.weber@nordwind.example
hrapi > use HRAPI-2026-001
hrapi > run
hrapi > use HRAPI-2026-003
hrapi > run
```

### Mode script (non interactif)

```bash
python3 hrapi.py -c "set email lena.weber@nordwind.example" \
                 -c "use HRAPI-2026-001" -c "run" \
                 -c "use HRAPI-2026-003" -c "run"
```

Option `--base` pour cibler une autre URL : `python3 hrapi.py --base http://host:4000`.

## Modules

| Module | CWE | CVSS | Description |
|---|---|---|---|
| HRAPI-2026-001 | CWE-640 | 9.8 | Jeton de reset renvoyé dans la réponse → prise de compte |
| HRAPI-2026-002 | CWE-639 | 9.1 | Lecture cross-tenant via `X-Organization-Id` |
| HRAPI-2026-003 | CWE-269 | 9.9 | Élévation vers `SUPER_ADMIN` |
| HRAPI-2026-004 | CWE-639 | 9.1 | IDOR : fiche employé d'un autre tenant par id |
| HRAPI-2026-005 | CWE-639 | 9.1 | Création d'un admin dans un autre tenant |
| HRAPI-2026-007 | CWE-918 | 9.1 | SSRF via `import-from-url` |
| HRAPI-2026-010 | CWE-798 | 9.8 | Forge de jeton (secret JWT par défaut) |
| HRAPI-2026-026 | CWE-22 | 9.1 | Écriture de fichier hors `uploads/` (path traversal) |

Le rapport complet (27 failles, mapping OWASP API Top 10, chaîne write-to-RCE)
est dans [`RAPPORT_VULNERABILITES.md`](RAPPORT_VULNERABILITES.md).

## Architecture

```
poc/
├── __main__.py        point d'entrée (console + mode script)
├── console.py         REPL (use / set / run / search / sessions …)
├── registry.py        découverte automatique des modules
├── client.py          primitives HTTP (une par endpoint faible)
└── modules/
    ├── base.py        socle (Module, Option, Context, datastore partagé)
    └── hrapi_2026_*.py  un module par faille
```

Les modules partagent un datastore : `HRAPI-2026-001` capture un token, les
autres l'enchaînent (clés `ACCESS`, `USER_ID`, `SESSION_ORG`, `SESSION_ROLE`,
`ORGS`). Ajouter un module = déposer un fichier `modules/*.py` exposant une
classe `Exploit` ; il est découvert automatiquement.
