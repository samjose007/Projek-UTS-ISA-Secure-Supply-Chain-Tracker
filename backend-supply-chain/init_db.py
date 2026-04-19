from database import engine
from models import schemas # Pastikan ini mengarah ke folder models kamu

def buat_tabel_sekarang():
    print("⏳ Menghubungkan ke Aiven Singapura...")
    try:
        # Perintah sakti untuk membuat semua tabel yang ada di models/schemas.py
        schemas.Base.metadata.create_all(bind=engine)
        print("✅ Berhasil! Semua tabel dan kolom sudah tercipta di Cloud.")
    except Exception as e:
        print(f"❌ Gagal: {e}")

if __name__ == "__main__":
    buat_tabel_sekarang()