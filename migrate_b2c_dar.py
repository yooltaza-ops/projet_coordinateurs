"""
Migration : ajouter la table seance_b2c_dar + migrer dar_id existant

Lance ce script UNE SEULE FOIS après avoir mis à jour models.py :
    python migrate_b2c_dar.py
"""

from app import app
from extensions import db
from models import SeanceB2C, Dour

# Table d'association (définie aussi dans models.py)
seance_b2c_dar = db.Table('seance_b2c_dar',
    db.Column('seance_b2c_id', db.Integer, db.ForeignKey('seance_b2c.id', ondelete='CASCADE')),
    db.Column('dour_id',       db.Integer, db.ForeignKey('dour.id',       ondelete='CASCADE'))
)

with app.app_context():

    # 1) Créer la table seance_b2c_dar si elle n'existe pas
    db.engine.execute("""
        CREATE TABLE IF NOT EXISTS seance_b2c_dar (
            seance_b2c_id INTEGER NOT NULL REFERENCES seance_b2c(id) ON DELETE CASCADE,
            dour_id       INTEGER NOT NULL REFERENCES dour(id)       ON DELETE CASCADE,
            PRIMARY KEY (seance_b2c_id, dour_id)
        )
    """)
    print("✅ Table seance_b2c_dar créée (ou déjà existante)")

    # 2) Migrer les dar_id existants → table junction
    #    (uniquement si la colonne dar_id existe encore dans seance_b2c)
    try:
        result = db.engine.execute("SELECT id, dar_id FROM seance_b2c WHERE dar_id IS NOT NULL")
        rows = result.fetchall()
        migrated = 0
        for row in rows:
            seance_id, dar_id = row[0], row[1]
            # Insérer dans la table junction si pas déjà là
            db.engine.execute("""
                INSERT OR IGNORE INTO seance_b2c_dar (seance_b2c_id, dour_id)
                VALUES (?, ?)
            """, (seance_id, dar_id))
            migrated += 1
        print(f"✅ {migrated} séance(s) migrées (dar_id → seance_b2c_dar)")
    except Exception as e:
        print(f"ℹ️  Migration dar_id skipped: {e}")

    # 3) (Optionnel) Supprimer la colonne dar_id de seance_b2c
    #    SQLite ne supporte pas DROP COLUMN directement — skip si SQLite
    #    Pour PostgreSQL/MySQL, décommenter :
    # try:
    #     db.engine.execute("ALTER TABLE seance_b2c DROP COLUMN dar_id")
    #     print("✅ Colonne dar_id supprimée de seance_b2c")
    # except Exception as e:
    #     print(f"ℹ️  Suppression dar_id skipped: {e}")

    print("\n✅ Migration terminée!")