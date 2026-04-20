from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from datetime import datetime
from database import get_db
from models.schemas import LogPelacakan, Pengiriman, Pengguna 
from security.blockchain import generate_hash
from security.rbac import role_required, SECRET_KEY, ALGORITHM
from jose import jwt 

router = APIRouter(prefix="/pelacakan", tags=["Logistik & Blockchain"])

class LogBaru(BaseModel):
    nomor_resi: str # Menggunakan resi agar kurir mudah input
    id_pengguna: int
    aksi_pelacakan: str 
    lokasi_pelacakan: str
    catatan_tambahan: str = None

@router.post("/update-status", dependencies=[Depends(role_required(["Kurir", "Admin"]))])
def update_status_barang(log_input: LogBaru, db: Session = Depends(get_db)):
    # 1. Validasi: Cari pengiriman berdasarkan nomor resi
    pengiriman = db.query(Pengiriman).filter(Pengiriman.nomor_resi == log_input.nomor_resi).first()
    
    if not pengiriman:
        raise HTTPException(status_code=404, detail="Nomor Resi tidak ditemukan di database. Pastikan resi valid!")

    # 2. VALIDASI KEAMANAN OTORISASI JASA LOGISTIK
    kurir = db.query(Pengguna).filter(Pengguna.id_pengguna == log_input.id_pengguna).first()
    
    if kurir and kurir.role == "Kurir":
        if kurir.jasa_logistik != pengiriman.ekspedisi_pilihan:
            # Jika beda jasa, lemparkan error "Tidak Ditemukan" (Bukan 403 Ditolak).
            # Ini adalah teknik keamanan (Information Hiding) agar penyerang / kurir iseng 
            # tidak tahu bahwa resi itu valid milik perusahaan sebelah.
            raise HTTPException(status_code=404, detail="Nomor Resi tidak ditemukan di database. Pastikan resi valid!")

    id_pengiriman_valid = pengiriman.id_pengiriman

    # 3. Update data utama di tabel pengiriman
    pengiriman.status_pengiriman = log_input.aksi_pelacakan
    pengiriman.lokasi_sekarang = log_input.lokasi_pelacakan
    pengiriman.id_kurir = log_input.id_pengguna
    pengiriman.waktu_diperbarui = datetime.utcnow()

    # 4. Cari log terakhir untuk menyambung rantai (Blockchain Hash)
    log_terakhir = db.query(LogPelacakan).\
        filter(LogPelacakan.id_pengiriman == id_pengiriman_valid).\
        order_by(desc(LogPelacakan.id_log)).first()

    hash_sebelumnya = log_terakhir.hash_sekarang if log_terakhir else "0" * 64
    waktu_sekarang = datetime.utcnow().replace(microsecond=0)
    
    hash_baru = generate_hash(
        id_log=0, 
        aksi_pelacakan=log_input.aksi_pelacakan,
        waktu_log=waktu_sekarang,
        hash_sebelumnya=hash_sebelumnya
    )

    # 5. Simpan Log Baru ke Rantai
    new_log = LogPelacakan(
        id_pengiriman=id_pengiriman_valid,
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

    return {
        "status": "sukses",
        "hash_terbentuk": hash_baru,
        "detail": f"Status resi {log_input.nomor_resi} berhasil diperbarui!"
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

@router.get("/all", dependencies=[Depends(role_required(["Admin"]))])
def get_all_pengiriman(request: Request, db: Session = Depends(get_db)):
    # 1. Buka Token untuk mengetahui Identitas Admin
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Sesi tidak valid")
    
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Token tidak valid")
    
    # 2. Cari data admin di tabel pengguna
    admin = db.query(Pengguna).filter(Pengguna.id_pengguna == user_id).first()
    
    if not admin or not admin.jasa_logistik:
        raise HTTPException(status_code=403, detail="Akses Ditolak: Profil Admin tidak memiliki detail perusahaan.")
        
    # 3. FILTERING (ISOLASI): Hanya ambil pengiriman yang ekspedisinya sama dengan perusahaan Admin
    pengiriman_list = db.query(Pengiriman).filter(Pengiriman.ekspedisi_pilihan == admin.jasa_logistik).all()
    
    hasil = []
    for p in pengiriman_list:
        supplier_name = p.produk.supplier.username if p.produk and p.produk.supplier else "Unknown"
        hasil.append({
            "id_pengiriman": p.id_pengiriman,
            "nomor_resi": p.nomor_resi,
            "supplier": supplier_name,
            "status_pengiriman": p.status_pengiriman
        })
    return hasil

# --- ENDPOINT LACAK RESI PUBLIK ---
@router.get("/track/{nomor_resi}")
def lacak_resi_publik(nomor_resi: str, db: Session = Depends(get_db)):
    # Cari pengiriman berdasarkan nomor resi
    pengiriman = db.query(Pengiriman).filter(Pengiriman.nomor_resi == nomor_resi).first()
    
    if not pengiriman:
        raise HTTPException(status_code=404, detail="Resi tidak ditemukan")
    
    # Kembalikan data untuk ditampilkan di frontend
    return {
        "nomor_resi": pengiriman.nomor_resi,
        "status_pengiriman": pengiriman.status_pengiriman,
        "lokasi_sekarang": pengiriman.lokasi_sekarang,
        "waktu_diperbarui": pengiriman.waktu_diperbarui.strftime("%d-%m-%Y %H:%M") if pengiriman.waktu_diperbarui else "Baru saja"
    }