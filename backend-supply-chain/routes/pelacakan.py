from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from datetime import datetime
from database import get_db
from models.schemas import LogPelacakan, Pengiriman
from security.blockchain import generate_hash
from security.rbac import role_required

router = APIRouter(prefix="/pelacakan", tags=["Logistik & Blockchain"])

class LogBaru(BaseModel):
    id_pengiriman: int
    id_pengguna: int
    aksi_pelacakan: str # Contoh: "Paket tiba di Gudang Surabaya"
    lokasi_pelacakan: str
    catatan_tambahan: str = None

@router.post("/update-status", dependencies=[Depends(role_required(["Kurir", "Admin"]))])
def update_status_barang(log_input: LogBaru, db: Session = Depends(get_db)):
    # 1. Cari log terakhir dari pengiriman ini untuk mengambil hash sebelumnya
    log_terakhir = db.query(LogPelacakan).\
        filter(LogPelacakan.id_pengiriman == log_input.id_pengiriman).\
        order_by(desc(LogPelacakan.id_log)).first()

    # 2. Tentukan hash sebelumnya (Jika pertama kali, pakai genesis hash: 64 nol)
    hash_sebelumnya = log_terakhir.hash_sekarang if log_terakhir else "0" * 64
    
    # 3. Siapkan objek log baru (Waktu ambil sekarang)
    waktu_sekarang = datetime.utcnow()
    
    # Kita butuh ID log selanjutnya (simulasi) atau biarkan DB generate dulu
    # Untuk hashing yang akurat, biasanya kita simpan dulu tanpa hash, lalu update.
    # Tapi untuk simplifikasi tugas ISA, kita hash data input + hash_sebelumnya.
    
    hash_baru = generate_hash(
        id_log=0, # Dummy ID karena belum masuk DB
        aksi_pelacakan=log_input.aksi_pelacakan,
        waktu_log=waktu_sekarang,
        hash_sebelumnya=hash_sebelumnya
    )

    new_log = LogPelacakan(
        id_pengiriman=log_input.id_pengiriman,
        id_pengguna=log_input.id_pengguna,
        aksi_pelacakan=log_input.aksi_pelacakan,
        lokasi_pelacakan=log_input.lokasi_pelacakan,
        catatan_tambahan=log_input.catatan_tambahan,
        waktu_log=waktu_sekarang,
        hash_sebelumnya=hash_sebelumnya,
        hash_sekarang=hash_baru
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return {
        "status": "Log Tercatat",
        "hash_terbentuk": hash_baru,
        "detail": "Data telah dikunci ke dalam rantai log."
    }

@router.get("/verifikasi/{id_pengiriman}")
def verifikasi_integritas_log(id_pengiriman: int, db: Session = Depends(get_db)):
    logs = db.query(LogPelacakan).\
        filter(LogPelacakan.id_pengiriman == id_pengiriman).\
        order_by(LogPelacakan.id_log).all()

    if not logs:
        raise HTTPException(status_code=404, detail="Belum ada log.")

    for i in range(len(logs)):
        current_log = logs[i]

        # 1. HITUNG ULANG HASH berdasarkan data yang ada di DB sekarang
        # Kita pakai ID 0 karena saat generate awal kita pakai dummy 0
        recalculated_hash = generate_hash(
            id_log=0, 
            aksi_pelacakan=current_log.aksi_pelacakan,
            waktu_log=current_log.waktu_log,
            hash_sebelumnya=current_log.hash_sebelumnya
        )

        # 2. CEK: Apakah isi datanya masih asli?
        if recalculated_hash != current_log.hash_sekarang:
            return {
                "integritas": "RUSAK!",
                "pesan": f"PERINGATAN! Data pada Log ID {current_log.id_log} telah diubah secara ilegal. Isi tidak sesuai dengan tanda tangan digitalnya!"
            }

        # 3. CEK: Apakah rantainya masih nyambung ke baris sebelumnya? (Kecuali baris pertama)
        if i > 0:
            if current_log.hash_sebelumnya != logs[i-1].hash_sekarang:
                return {
                    "integritas": "RANTAI PUTUS!",
                    "pesan": f"Log ID {current_log.id_log} mencoba menyambung ke hash yang salah!"
                }
            
    return {
        "integritas": "AMAN",
        "pesan": "Semua data asli dan urutan rantai valid."
    }