import os
import pyotp
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from database import get_db
from models.schemas import Pengguna
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from jose import jwt
from security.rbac import SECRET_KEY, ALGORITHM
from pydantic import BaseModel
from typing import Optional
import urllib.parse

router = APIRouter(prefix="/auth", tags=["Autentikasi & Keamanan"])

# --- SETUP OAUTH GOOGLE ---
config = Config(".env")
oauth = OAuth(config)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- ROUTE LOGIN GOOGLE ---
@router.get("/login")
async def login_via_google(request: Request, role: str = "Supplier", mode: str = "login"):
    # Titip ROLE dan MODE di session
    request.session['requested_role'] = role
    request.session['auth_mode'] = mode
    
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, prompt='select_account')

# --- FITUR REGISTER & LOGIN ---
@router.get("/callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        email_google = user_info.get("email")
        
        mode = request.session.get('auth_mode', 'login')
        user_db = db.query(Pengguna).filter(Pengguna.email == email_google).first()

        # SKENARIO 1: Mau Daftar, tapi Email sudah ada
        if mode == 'register' and user_db:
            return HTMLResponse(content=f"""
                <script>
                    alert(`Gagal Daftar: Email {email_google} sudah terdaftar! Silakan gunakan menu Login.`);
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html';
                </script>
            """)

        # SKENARIO 2: Mau Login, tapi Email belum ada
        if mode == 'login' and not user_db:
            return HTMLResponse(content="""
                <script>
                    alert(`Email tidak ditemukan! Silakan daftar akun terlebih dahulu.`);
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html';
                </script>
            """)

        # SKENARIO 3: User DAFTAR BARU
        if mode == 'register' and not user_db:
            request.session['temp_email'] = email_google
            request.session['temp_nama'] = user_info.get("name")
            return HTMLResponse(content=f"""
                <script>
                    alert(`Autentikasi Google Berhasil! Silakan lengkapi peran dan jasa logistik Anda.`);
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/setup-role.html';
                </script>
            """)

        # SKENARIO 4: LOGIN BERHASIL
        if user_db.totp_secret:
            # JIKA PUNYA 2FA: Buat token sementara, lempar ke halaman depan untuk minta OTP
            temp_data = {"sub": str(user_db.id_pengguna), "type": "temp_2fa"}
            temp_token = jwt.encode(temp_data, SECRET_KEY, algorithm=ALGORITHM)
            return HTMLResponse(content=f"""
                <script>
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html?require_2fa=true&temp_token={temp_token}';
                </script>
            """)
        else:
            # JIKA TIDAK PUNYA 2FA: Langsung masuk seperti biasa
            token_data = {"role": user_db.role, "sub": str(user_db.id_pengguna)}
            access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
            target_dashboard = f"dashboard-{user_db.role.lower()}.html"
            
            return HTMLResponse(content=f"""
                <script>
                    const targetUrl = 'http://127.0.0.1:5500/frontend-supply-chain/{target_dashboard}?token={access_token}&role={user_db.role}&username=' + encodeURIComponent('{user_db.username}');
                    window.location.href = targetUrl;
                </script>
            """)
    except Exception as e:
        # Menghapus karakter backtick dari pesan error agar tidak merusak JS
        error_msg = str(e).replace('`', "'")
        return HTMLResponse(content=f"""
            <script>
                alert(`Terjadi Error: {error_msg}`);
                window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html';
            </script>
        """)

class FinalisasiRegister(BaseModel):
    role: str
    jasa_logistik: Optional[str] = None # Opsional untuk Supplier

@router.post("/complete-registration")
def selesaikan_pendaftaran(data: FinalisasiRegister, request: Request, db: Session = Depends(get_db)):
    email_baru = request.session.get('temp_email')
    nama_baru = request.session.get('temp_nama', 'User')

    if not email_baru:
        raise HTTPException(status_code=400, detail="Sesi pendaftaran habis. Ulangi login Google.")

    # 1. Insert ke Database sekarang
    user_baru = Pengguna(
        username=email_baru.split('@')[0],
        email=email_baru,
        password_hash="sso_google_account",
        role=data.role,
        jasa_logistik=data.jasa_logistik
    )
    db.add(user_baru)
    db.commit()
    db.refresh(user_baru)

    # 2. Hapus session agar bersih
    request.session.pop('temp_email', None)
    request.session.pop('temp_nama', None)

    return {"status": "sukses", "pesan": "Akun berhasil dibuat! Silakan login di halaman utama."}

# --- FITUR 2FA ---
class VerifySetup(BaseModel):
    secret: str
    kode_otp: str

@router.get("/2fa/generate")
def generate_2fa_secret(request: Request, db: Session = Depends(get_db)):
    # 1. Ambil ID User dari Token JWT (Otorisasi)
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Sesi tidak valid")
    
    token = auth_header.split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id = int(payload.get("sub"))
    
    user = db.query(Pengguna).filter(Pengguna.id_pengguna == user_id).first()
    
    # 2. Buat Kunci Rahasia dan URI Authenticator
    secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Secure Supply Chain ISA")
    
    # 3. Konversi URI jadi QR Code Image menggunakan API eksternal agar mudah di-scan
    encoded_uri = urllib.parse.quote(totp_uri)
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?data={encoded_uri}&size=200x200"
    
    return {
        "secret_key": secret,
        "qr_code_url": qr_url
    }

class VerifyLogin2FA(BaseModel):
    temp_token: str
    kode_otp: str

@router.post("/2fa/verify-login")
def verify_login_2fa(data: VerifyLogin2FA, db: Session = Depends(get_db)):
    try:
        # Dekode token sementara
        payload = jwt.decode(data.temp_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "temp_2fa":
            raise HTTPException(status_code=400, detail="Token tidak valid")
        
        user_id = int(payload.get("sub"))
        user = db.query(Pengguna).filter(Pengguna.id_pengguna == user_id).first()
        
        # Cek OTP dengan secret di database
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(data.kode_otp):
            # Jika benar, berikan Token Asli
            token_data = {"role": user.role, "sub": str(user.id_pengguna)}
            access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
            return {
                "access_token": access_token,
                "role": user.role,
                "username": user.username
            }
        else:
            raise HTTPException(status_code=401, detail="Kode OTP Salah atau Expired!")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Sesi login kedaluwarsa, silakan login ulang.")