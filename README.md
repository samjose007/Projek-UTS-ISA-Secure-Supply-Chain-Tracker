# 🛡️ Secure Supply Chain Tracker

Sebuah prototipe sistem pelacakan logistik *end-to-end* yang dirancang dengan arsitektur keamanan tingkat tinggi. Proyek ini dikembangkan untuk mendemonstrasikan implementasi keamanan sistem informasi di dunia nyata, meliputi autentikasi berlapis, kriptografi data, dan integritas log pelacakan.

---

## ✨ Fitur Keamanan Utama (Security Features)

Sistem ini dibangun dengan mengedepankan prinsip *Defense in Depth* dan *CIA Triad*:

* 🔐 **Single Sign-On (SSO) via Google OAuth2:** Autentikasi modern yang mulus tanpa perlu menyimpan *plaintext password* pengguna.
* 📱 **Two-Factor Authentication (2FA / TOTP):** Lapisan keamanan kedua menggunakan algoritma *Time-based One-Time Password* yang terintegrasi dengan Google Authenticator/Authy.
* 🛡️ **Role-Based Access Control (RBAC) via JWT:** Pembatasan akses *endpoint* API secara ketat berdasarkan *role* (Admin, Supplier, Kurir) menggunakan JSON Web Tokens.
* 🔒 **Data Confidentiality (AES-256 Encryption):** Melindungi data sensitif (seperti deskripsi produk rahasia) di dalam *database* menggunakan enkripsi *symmetric* AES.
* 🔗 **Data Integrity (Blockchain-like Hash Chaining):** Mencegah manipulasi status pengiriman barang dengan algoritma **SHA-256**. Setiap log terikat dengan *hash* dari log sebelumnya (sistem anti-sangkalan).
* 📝 **Audit Trail System:** Pencatatan otomatis (Accountability) untuk setiap tindakan krusial (seperti menambah produk) ke dalam tabel `log_audit`.

---

## 🛠️ Teknologi yang Digunakan (Tech Stack)

**Backend:**
* **Framework:** FastAPI (Python)
* **Database ORM:** SQLAlchemy
* **Authentication:** Authlib (Google OAuth), PyOTP, Python-JOSE (JWT)
* **Cryptography:** Cryptography (Fernet/AES), hashlib (SHA-256)
* **Server:** Uvicorn

**Frontend:**
* HTML5, CSS3, Vanilla JavaScript (Fetch API)
* *Deployment:* Live Server (Local)

---

## 🚀 Cara Instalasi & Menjalankan Sistem

### 1. Persiapan Environment
Pastikan Anda sudah menginstal Python (>= 3.9) dan sistem *database* (seperti XAMPP/MySQL).

Kloning repositori ini ke mesin lokal Anda:
```bash
git clone [https://github.com/USERNAME_ANDA/Projek-UTS-ISA-Secure-Supply-Chain.git](https://github.com/USERNAME_ANDA/Projek-UTS-ISA-Secure-Supply-Chain.git)
cd Projek-UTS-ISA-Secure-Supply-Chain
