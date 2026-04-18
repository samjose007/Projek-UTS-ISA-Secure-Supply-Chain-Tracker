from sqlalchemy.orm import Session
from models.schemas import LogAudit
import datetime

def record_audit(db: Session, id_pengguna: int, tipe_aksi: str, nama_tabel: str, id_rekaman: int = None, status_lama: str = None, status_baru: str = None):
    """
    Fungsi universal untuk mencatat aktivitas user ke database.
    """
    audit_entry = LogAudit(
        id_pengguna=id_pengguna,
        tipe_aksi=tipe_aksi,
        nama_tabel=nama_tabel,
        id_rekaman=id_rekaman,
        status_lama=status_lama,
        status_baru=status_baru,
        waktu_audit=datetime.datetime.utcnow()
    )
    db.add(audit_entry)
    db.commit()