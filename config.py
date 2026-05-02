class Config:
    SQLALCHEMY_DATABASE_URI = (
        "mysql+pymysql://root:@localhost/gestion_coordinateurs"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "cle_secrete_tazas_2026"