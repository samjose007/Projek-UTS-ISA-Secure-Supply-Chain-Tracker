from database import engine
from sqlalchemy import text

print("Menambahkan kolom 2FA ke tabel pengguna...")
try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE pengguna ADD COLUMN totp_secret VARCHAR(50);"))
        conn.commit()
    print("✅ Berhasil! Kolom 2FA sudah ditambahkan ke Aiven.")
except Exception as e:
    print(f"Pesan: {e}")