"""
Point d'entree de la console d'exploitation.

Usage :
    python3 -m poc                         # console interactive
    python3 -m poc --base http://host:4000
    python3 -m poc -c "use HRAPI-2026-001" -c "set email a@b" -c "run"   # script

A n'utiliser que sur une instance dont on possede l'autorisation explicite.
"""

from __future__ import annotations
import argparse
import sys

from .console import Console


def main() -> int:
    p = argparse.ArgumentParser(prog="poc", description="Console d'audit hr-management-api")
    p.add_argument("--base", default="http://localhost:4000", help="URL de base de l'API")
    p.add_argument("-c", "--command", action="append", default=[],
                   help="commande a jouer automatiquement (repetable)")
    args = p.parse_args()

    console = Console(args.base)

    # Mode script : on enchaine les -c puis on rend la main (ou on quitte).
    if args.command:
        for cmd in args.command:
            print(f"\nhrapi> {cmd}")
            if console.onecmd(cmd):
                return 0
        return 0

    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n  interrompu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
