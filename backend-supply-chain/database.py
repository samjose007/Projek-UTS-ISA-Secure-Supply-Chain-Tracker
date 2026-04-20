from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base 
import os
from dotenv import load_dotenv 

load_dotenv()

# Ambil URL dari .env
SQLALCHEMY_DATABASE_URL = os.getenv("DB_URL", "mysql+pymysql://root:@localhost:3306/supply_chain_db")

# --- LOGIKA PENANGANAN SSL UNTUK AIVEN (PYMYSQL) ---
# PyMySQL akan error jika ada string '?ssl-mode=REQUIRED' di URL.
# Jadi kita potong string tersebut, lalu kita masukkan konfigurasi SSL lewat connect_args.

if "?ssl-mode=REQUIRED" in SQLALCHEMY_DATABASE_URL:
    clean_url = SQLALCHEMY_DATABASE_URL.replace("?ssl-mode=REQUIRED", "")
    args_koneksi = {"ssl": {}} # Memaksa PyMySQL menggunakan mode SSL aman
elif "?ssl_mode=REQUIRED" in SQLALCHEMY_DATABASE_URL:
    clean_url = SQLALCHEMY_DATABASE_URL.replace("?ssl_mode=REQUIRED", "")
    args_koneksi = {"ssl": {}}
else:
    clean_url = SQLALCHEMY_DATABASE_URL
    args_koneksi = {} # Untuk localhost / XAMPP biasa yang tidak butuh SSL

# Buat engine dengan parameter yang sudah disesuaikan
engine = create_engine(
    clean_url, 
    connect_args=args_koneksi,
    pool_pre_ping=True,   # Memaksa SQLAlchemy mengecek koneksi mati/hidup sebelum query
    pool_recycle=300      # Memaksa SQLAlchemy membuat ulang koneksi setiap 5 menit (300 detik)
)
Sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = Sessionlocal()
    try: 
        yield db
    finally: 
        db.close()