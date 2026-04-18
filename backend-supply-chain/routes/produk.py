from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import get_db
from models.schemas import Produk
from security.encryption import encrypt_data
from security.audit import record_audit
from security.rbac import role_required

router = APIRouter(prefix="/produk", tags=["Manajemen Produk"])

class ProdukBaru(BaseModel):
    id_supplier: int
    nama_produk: str
    deskripsi_produk: str

# Hanya Supplier dan Admin yang boleh nambah produk
@router.post("/tambah", dependencies=[Depends(role_required(["Supplier", "Admin"]))])
def tambah_produk(produk_input: ProdukBaru, db: Session = Depends(get_db)):
    try:
        # 1. Enkripsi data sensitif
        deskripsi_rahasia = encrypt_data(produk_input.deskripsi_produk)

        # 2. Simpan ke Database
        db_produk = Produk(
            id_supplier=produk_input.id_supplier,
            nama_produk=produk_input.nama_produk,
            deskripsi_produk=deskripsi_rahasia
        )
        db.add(db_produk)
        db.commit()
        db.refresh(db_produk)

        # 3. Catat ke Audit Log (Accountability)
        record_audit(
            db=db,
            id_pengguna=produk_input.id_supplier,
            tipe_aksi="INSERT",
            nama_tabel="produk",
            id_rekaman=db_produk.id_produk,
            status_baru=f"Produk Baru: {db_produk.nama_produk}"
        )

        return {
            "status": "sukses",
            "pesan": "Produk berhasil diamankan",
            "id_produk": db_produk.id_produk
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Gagal: {str(e)}")