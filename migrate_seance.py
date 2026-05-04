"""
Migration: zid colonnes matiere + niveau f table seance
─────────────────────────────────────────────────────────
Kifash tdir:
  1. Kopyi had fichier f root dyal projet dyalek
  2. Run:  python migrate_seance.py
"""

from app import app
from models import db

with app.app_context():
    with db.engine.connect() as conn:
        # SQLite — ALTER TABLE ADD COLUMN (imkn tzid column wahda b wahda)
        try:
            conn.execute(db.text(
                "ALTER TABLE seance ADD COLUMN matiere VARCHAR(100)"
            ))
            print("✅ Colonne 'matiere' zdat b-njah")
        except Exception as e:
            print(f"⚠️  matiere: {e}")

        try:
            conn.execute(db.text(
                "ALTER TABLE seance ADD COLUMN niveau VARCHAR(100)"
            ))
            print("✅ Colonne 'niveau' zdat b-njah")
        except Exception as e:
            print(f"⚠️  niveau: {e}")

        conn.commit()

    print("\n🎉 Migration kamlat — restart Flask dyalek")