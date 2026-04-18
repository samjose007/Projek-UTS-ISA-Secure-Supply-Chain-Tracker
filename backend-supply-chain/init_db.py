# init_db.py
from database import engine, Base
from models import schemas # Pastikan path ini benar sesuai strukturmu

print("Sedang membuat tabel di database...")
try:
    # Ini akan membuat semua tabel yang terdaftar di Base.metadata
    Base.metadata.create_all(bind=engine)
    print("Berhasil! Silakan cek phpMyAdmin, tabel seharusnya sudah muncul.")
except Exception as e:
    print(f"Gagal konek ke database: {e}")

