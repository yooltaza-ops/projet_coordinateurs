from app import app
from models import db, Professeur, PROFESSEURS_LISTE

with app.app_context():
    db.create_all()
    if Professeur.query.count() == 0:
        for nom in PROFESSEURS_LISTE:
            db.session.add(Professeur(nom=nom.strip()))
        db.session.commit()
        print(f"✅ {len(PROFESSEURS_LISTE)} professeurs ajoutés!")
    else:
        print("⚠️  Professeurs déjà existants — seed ignoré.")
        print(f"   (Total actuel: {Professeur.query.count()} profs)")