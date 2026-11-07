
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    # Local MySQL settings (kept as backup)
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")

    # Online TiDB settings
    TIDB_HOST = os.getenv("TIDB_HOST")
    TIDB_PORT = int(os.getenv("TIDB_PORT", "4000"))
    TIDB_USER = os.getenv("TIDB_USER")
    TIDB_PASSWORD = os.getenv("TIDB_PASSWORD")
    TIDB_NAME = os.getenv("TIDB_NAME", "gdms")

    # SSL certificate
    TIDB_SSL_CA = os.path.join(
        BASE_DIR,
        os.getenv("TIDB_SSL_CA", "certs/isrgrootx1.pem")
    )
