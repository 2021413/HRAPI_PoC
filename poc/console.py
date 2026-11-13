"""
Console interactive (façon metasploit) pour piloter les modules d'exploitation.

Commandes :
  show modules | modules          liste les modules
  search <texte>                  filtre les modules
  use <id|index>                  sélectionne un module
  info                            détail du module courant
  options | show options          options + datastore
  set <clef> <valeur>             règle une option (ou une var globale, ex: set email ..)
  unset <clef>                    efface une option
  run | exploit                   lance le module courant
  sessions                        état capturé (token, rôle, orgs)
  back                            désélectionne le module
  help                            aide
  exit | quit                     quitter

Les clefs connues globalement (datastore) : EMAIL, BASE, ORG, NEWPASS, ACCESS...
`set email x` alimente le datastore et sert de défaut à tous les modules.
"""

from __future__ import annotations
import cmd

from .client import Client
from .registry import load_modules
from .modules.base import Context


class Console(cmd.Cmd):
    intro = (
        "\n  hr-management-api — console d'exploitation (instance autorisée uniquement)\n"
        "  'show modules' pour lister, 'use <id>' pour choisir, 'help' pour l'aide.\n"
    )

    def __init__(self, base: str):
        super().__init__()
        self.modules = load_modules()
        self.store: dict = {"BASE": base}
        self.client = Client(base)
        self.current = None
        self._set_prompt()

    # --- helpers ------------------------------------------------------------

    def _set_prompt(self) -> None:
        if self.current:
            self.prompt = f"hrapi ({self.current.id}) > "
        else:
            self.prompt = "hrapi > "

    def ok(self, m): print(f"  [+] {m}")
    def info(self, m): print(f"  [*] {m}")
    def fail(self, m): print(f"  [-] {m}")
    def line(self, m): print(m)

    def _ctx(self) -> Context:
        return Context(self.client, self.store, self.ok, self.info, self.fail, self.line)

    def _resolve(self, ident: str):
        ident = ident.strip()
        if ident in self.modules:
            return self.modules[ident]
        # tolérance : casse, et recherche par index
        up = ident.upper()
        for mid, mod in self.modules.items():
            if mid.upper() == up:
                return mod
        if ident.isdigit():
            items = list(self.modules.values())
            i = int(ident)
            if 0 <= i < len(items):
                return items[i]
        # correspondance par nom partiel
        for mod in self.modules.values():
            if ident.lower() in mod.name.lower():
                return mod
        return None

    # --- commandes ----------------------------------------------------------

    def do_modules(self, _):
        """Liste les modules disponibles."""
        print("\n  #  Module            CVSS            Nom")
        print("  -- ----------------  --------------  ----------------------------------")
        for i, mod in enumerate(self.modules.values()):
            print(f"  {i:<2} {mod.id:<16}  {mod.cvss:<14}  {mod.name}")
        print()

    def do_show(self, arg):
        """show modules | show options"""
        a = arg.strip().lower()
        if a in ("options", "option"):
            self.do_options("")
        else:
            self.do_modules("")

    def do_search(self, arg):
        """search <texte> — filtre par id, nom ou description."""
        q = arg.strip().lower()
        hits = [m for m in self.modules.values()
                if q in m.id.lower() or q in m.name.lower() or q in m.description.lower()]
        if not hits:
            self.fail("Aucun module.")
            return
        for m in hits:
            print(f"  {m.id:<16} {m.name}")

    def do_use(self, arg):
        """use <id|index|nom> — sélectionne un module."""
        mod = self._resolve(arg)
        if not mod:
            self.fail(f"Module introuvable : {arg!r}. Essaie 'show modules'.")
            return
        self.current = mod
        self._set_prompt()
        self.ok(f"Module sélectionné : {mod.id} ({mod.name})")

    def do_info(self, _):
        """Détail du module courant."""
        m = self.current
        if not m:
            self.fail("Aucun module sélectionné.")
            return
        print(f"\n  {m.id} — {m.name}")
        print(f"  CWE   : {m.cwe}")
        print(f"  CVSS  : {m.cvss}")
        print(f"  Desc  : {m.description}\n")
        self.do_options("")

    def do_options(self, _):
        """Options du module courant + datastore global."""
        if self.current:
            print(f"\n  Options de {self.current.id} :")
            print("    Clef        Obl.  Valeur courante           Aide")
            for k, spec in self.current.options.items():
                val = self.current.opt(self.store, k)
                req = "oui" if spec.required else "non"
                print(f"    {k:<11} {req:<5} {str(val):<25} {spec.help}")
            miss = self.current.missing(self.store)
            if miss:
                self.fail(f"Options obligatoires manquantes : {', '.join(miss)}")
        globals_ = {k: v for k, v in self.store.items() if k not in ("ACCESS", "ORGS")}
        print(f"\n  Datastore global : {globals_}")
        if "ACCESS" in self.store:
            print(f"  Session : token présent, rôle={self.store.get('SESSION_ROLE')}")
        print()

    def do_set(self, arg):
        """set <clef> <valeur> — option du module, ou variable globale."""
        parts = arg.split(None, 1)
        if len(parts) < 2:
            self.fail("Usage : set <clef> <valeur>")
            return
        key, val = parts[0], parts[1].strip()
        if self.current and key.lower() in self.current.options:
            self.current.values[key.lower()] = val
            self.ok(f"{self.current.id}.{key.lower()} = {val}")
        else:
            # variable globale (EMAIL, ORG, NEWPASS, BASE...)
            self.store[key.upper()] = val
            self.ok(f"{key.upper()} = {val}  (datastore global)")
            if key.upper() == "BASE":
                self.client = Client(val)
                self.info("Client HTTP reconfiguré.")

    def do_unset(self, arg):
        """unset <clef>"""
        key = arg.strip()
        if self.current and key.lower() in self.current.values:
            del self.current.values[key.lower()]
            self.ok(f"option {key} effacée")
        elif key.upper() in self.store:
            del self.store[key.upper()]
            self.ok(f"{key.upper()} effacée")
        else:
            self.fail("Clef inconnue.")

    def do_run(self, _):
        """Lance le module courant."""
        m = self.current
        if not m:
            self.fail("Aucun module sélectionné. 'use <id>' d'abord.")
            return
        miss = m.missing(self.store)
        if miss:
            self.fail(f"Options manquantes : {', '.join(miss)}")
            return
        print(f"\n{'='*70}\n[{m.id}] {m.name}\n{'='*70}")
        try:
            m.run(self._ctx())
        except Exception as e:  # noqa: BLE001 — PoC, on affiche l'erreur telle quelle
            self.fail(f"Erreur pendant l'exécution : {e}")

    def do_exploit(self, arg):
        """Alias de run."""
        self.do_run(arg)

    def do_sessions(self, _):
        """État capturé pendant la chaîne (token, rôle, orgs)."""
        if "ACCESS" not in self.store:
            self.info("Aucune session capturée.")
            return
        print(f"  Rôle courant : {self.store.get('SESSION_ROLE')}")
        print(f"  User ID      : {self.store.get('USER_ID')}")
        print(f"  Org          : {self.store.get('SESSION_ORG')}")
        tok = self.store.get("ACCESS", "")
        print(f"  Access token : {tok[:40]}...")
        if self.store.get("ORGS"):
            print(f"  Organisations visibles : {len(self.store['ORGS'])}")

    def do_back(self, _):
        """Désélectionne le module."""
        self.current = None
        self._set_prompt()

    def do_exit(self, _):
        """Quitter."""
        print("  bye.")
        return True

    def do_quit(self, arg):
        """Quitter."""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    def emptyline(self):
        pass
