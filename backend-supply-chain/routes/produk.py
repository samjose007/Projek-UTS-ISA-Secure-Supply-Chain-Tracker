from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import get_db
from models.schemas import Produk, Pengiriman
from security.encryption import encrypt_data
from security.audit import record_audit
from security.rbac import role_required
import random
import string

router = APIRouter(prefix="/produk", tags=["Manajemen Produk"])

class ProdukBaru(BaseModel):
    id_supplier: int
    nama_produk: str
    deskripsi_produk: str
    nama_penerima: str
    alamat_penerima: str
    jasa_pengiriman: str

@router.post("/tambah", dependencies=[Depends(role_required(["Supplier", "Admin"]))])
def tambah_produk(produk_input: ProdukBaru, db: Session = Depends(get_db)):
    try:
        # 1. ENKRIPSI GANDA (CIA Triad: Confidentiality)
        deskripsi_rahasia = encrypt_data(produk_input.deskripsi_produk)
        alamat_rahasia = encrypt_data(produk_input.alamat_penerima) # Alamat dienkripsi

        # 2. Simpan Produk ke Database
        db_produk = Produk(
            id_supplier=produk_input.id_supplier,
            nama_produk=produk_input.nama_produk,
            deskripsi_produk=deskripsi_rahasia
        )
        db.add(db_produk)
        db.commit()
        db.refresh(db_produk)

        # 3. ALGORITMA GENERATE RESI UNIK
        acak = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        resi_baru = f"TRX-26-{acak}"

        # 4. Buat Jadwal Pengiriman (Barang siap dijemput)
        db_pengiriman = Pengiriman(
            id_produk=db_produk.id_produk,
            status_pengiriman="Menunggu Penjemputan",
            lokasi_sekarang="Gudang Supplier",
            nomor_resi=resi_baru,
            nama_penerima=produk_input.nama_penerima,
            alamat_penerima=alamat_rahasia, # Simpan versi enkripsi
            ekspedisi_pilihan=produk_input.jasa_pengiriman
        )
        db.add(db_pengiriman)
        db.commit()

        # 5. Catat Audit Log
        record_audit(db, id_pengguna=produk_input.id_supplier, tipe_aksi="INSERT", nama_tabel="produk_pengiriman", id_rekaman=db_produk.id_produk, status_baru=f"Resi dibuat: {resi_baru}")

        return {
            "status": "sukses",
            "nomor_resi": resi_baru,
            "pesan": f"Data diamankan. Resi {resi_baru} berhasil dibuat!"
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Gagal: {str(e)}")