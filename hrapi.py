#!/usr/bin/env python3
"""
Lanceur autonome de la console d'exploitation hr-management-api.

Marche depuis n'importe quel dossier :
    python3 /home/hugo/Documents/sec-api/hrapi.py
    ./hrapi.py              (si rendu executable : chmod +x hrapi.py)

Options identiques a `python3 -m poc` :
    ./hrapi.py --base http://localhost:4000
    ./hrapi.py -c "use HRAPI-2026-001" -c "set email a@b" -c "run"
"""
import os
import sys

# Rend le package `poc` importable quel que soit le repertoire courant.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from poc.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
