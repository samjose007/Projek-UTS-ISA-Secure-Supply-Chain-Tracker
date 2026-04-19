from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, CHAR 
from sqlalchemy.orm import relationship 
from database import Base
import datetime 

class Pengguna(Base):
    __tablename__ = "pengguna"

    # PK diubah jadi id_pengguna agar cocok dengan FK di tabel lain
    id_pengguna = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False) # 'Admin', 'Supplier', 'Kurir'
    waktu_dibuat = Column(DateTime, default=datetime.datetime.utcnow)
    email = Column(String(45))
    jasa_logistik = Column(String(100), nullable=True)
    totp_secret = Column(String(50), nullable=True) # Kunci rahasia 2FA

    # Relasi
    produk = relationship("Produk", back_populates="supplier")
    pengiriman = relationship("Pengiriman", back_populates="kurir")
    log_pelacakan = relationship("LogPelacakan", back_populates="pengguna")
    log_audit = relationship("LogAudit", back_populates="pengguna")

class Produk(Base):
    __tablename__ = "produk"

    # PK diubah jadi id_produk agar cocok dengan FK di tabel pengiriman
    id_produk = Column(Integer, primary_key=True, index=True) 
    id_supplier = Column(Integer, ForeignKey("pengguna.id_pengguna")) 
    nama_produk = Column(String(150), unique=True, nullable=False)
    deskripsi_produk = Column(String(500), nullable=False)
    waktu_dibuat = Column(DateTime, default=datetime.datetime.utcnow)

    supplier = relationship("Pengguna", back_populates="produk")
    pengiriman = relationship("Pengiriman", back_populates="produk")

class Pengiriman(Base):
    __tablename__ = "pengiriman"

    id_pengiriman = Column(Integer, primary_key=True, index=True)
    id_produk = Column(Integer, ForeignKey("produk.id_produk"))
    status_pengiriman = Column(String(50))
    lokasi_sekarang = Column(String(255))
    id_kurir = Column(Integer, ForeignKey("pengguna.id_pengguna"))
    waktu_diperbarui = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    nomor_resi = Column(String(50), unique=True, index=True)
    nama_penerima = Column(String(100))
    alamat_penerima = Column(String(500)) # Butuh string panjang karena akan dienkripsi AES
    ekspedisi_pilihan = Column(String(100))

    produk = relationship("Produk", back_populates="pengiriman")
    kurir = relationship("Pengguna", back_populates="pengiriman") 
    log_pelacakan = relationship("LogPelacakan", back_populates="pengiriman")

class LogPelacakan(Base):
    __tablename__ = "log_pelacakan"

    id_log = Column(Integer, primary_key=True, index=True)
    id_pengiriman = Column(Integer, ForeignKey("pengiriman.id_pengiriman"))
    id_pengguna = Column(Integer, ForeignKey("pengguna.id_pengguna"))
    aksi_pelacakan = Column(String(50))
    lokasi_pelacakan = Column(String(255))
    catatan_tambahan = Column(String(500))
    waktu_log = Column(DateTime, default=datetime.datetime.utcnow)
    hash_sebelumnya = Column(CHAR(64))
    hash_sekarang = Column(CHAR(64))

    pengiriman = relationship("Pengiriman", back_populates="log_pelacakan")
    pengguna = relationship("Pengguna", back_populates="log_pelacakan")

class LogAudit(Base):
    __tablename__ = "log_audit"

    id_audit = Column(Integer, primary_key=True, index=True)
    id_pengguna = Column(Integer, ForeignKey("pengguna.id_pengguna"))
    tipe_aksi = Column(String(30))
    nama_tabel = Column(String(50))
    id_rekaman = Column(Integer)
    status_lama = Column(String(1000))
    status_baru = Column(String(1000))
    waktu_audit = Column(DateTime, default=datetime.datetime.utcnow)

    pengguna = relationship("Pengguna", back_populates="log_audit")