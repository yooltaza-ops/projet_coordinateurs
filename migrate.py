"""
migrate.py — Script migration bach tzid les nouvelles colonnes f la base existante
Run: python migrate.py
"""
import sqlite3
import os

# ─── Config ───────────────────────────────────────────────────────────────────
# Beddel had le chemin ila kanet base dyalek f makane okhar
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'yool.db')

# Ila mashi sqlite, commentaire had les lignes w utilisez Flask-Migrate
# ─────────────────────────────────────────────────────────────────────────────

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"❌ Base n'existe pas: {DB_PATH}")
        print("Vérifiez le chemin ou lancez l'app d'abord.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # ── 1. Zid matiere f coordinateur ────────────────────────────────────────
    try:
        cur.execute("ALTER TABLE coordinateur ADD COLUMN matiere VARCHAR(100)")
        print("✅ Colonne 'matiere' ajoutée à coordinateur")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e).lower():
            print("⏭️  'matiere' existe déjà — skip")
        else:
            print(f"⚠️  matiere: {e}")

    # ── 2. Zid niveau f coordinateur ─────────────────────────────────────────
    try:
        cur.execute("ALTER TABLE coordinateur ADD COLUMN niveau VARCHAR(100)")
        print("✅ Colonne 'niveau' ajoutée à coordinateur")
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e).lower():
            print("⏭️  'niveau' existe déjà — skip")
        else:
            print(f"⚠️  niveau: {e}")

    # ── 3. Créer table presence ───────────────────────────────────────────────
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS presence (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                coordinateur_id INTEGER NOT NULL REFERENCES coordinateur(id),
                date            DATE    NOT NULL,
                mois            INTEGER NOT NULL,
                annee           INTEGER NOT NULL,
                statut          VARCHAR(10) NOT NULL DEFAULT 'present'
                                CHECK(statut IN ('present','absent','justifie')),
                note            VARCHAR(300),
                created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(coordinateur_id, date)
            )
        """)
        print("✅ Table 'presence' créée")
    except sqlite3.OperationalError as e:
        print(f"⚠️  presence: {e}")

    conn.commit()
    conn.close()
    print("\n🎉 Migration terminée avec succès!")
    print("Redémarrez votre app Flask maintenant.")


if __name__ == '__main__':
    migrate()