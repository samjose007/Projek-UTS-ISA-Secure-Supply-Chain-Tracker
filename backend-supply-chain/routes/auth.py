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

router = APIRouter(prefix="/auth", tags=["Autentikasi & Keamanan"])

# --- 1. SETUP OAUTH GOOGLE ---
config = Config(".env")
oauth = OAuth(config)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- 2. ROUTE LOGIN GOOGLE ---
@router.get("/login")
async def login_via_google(request: Request, role: str = "Supplier", mode: str = "login"):
    # Titip ROLE dan MODE di session
    request.session['requested_role'] = role
    request.session['auth_mode'] = mode
    
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        email_google = user_info.get("email")
        
        # Ambil niat user dari session (login atau register?)
        mode = request.session.get('auth_mode', 'login')
        user_db = db.query(Pengguna).filter(Pengguna.email == email_google).first()

        # --- LOGIKA PENGECEKAN KEAMANAN (ISA) ---
        
        # SKENARIO A: User mau DAFTAR, tapi email SUDAH ADA
        if mode == 'register' and user_db:
            return HTMLResponse(content=f"""
                <script>
                    alert('Gagal Daftar: Email {email_google} sudah terdaftar! Silakan gunakan menu Login.');
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html';
                </script>
            """)

        # SKENARIO B: User mau LOGIN, tapi email BELUM TERDAFTAR
        if mode == 'login' and not user_db:
            return HTMLResponse(content="""
                <script>
                    alert('Email tidak ditemukan! Silakan daftar akun terlebih dahulu.');
                    window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/index.html';
                </script>
            """)

        # SKENARIO C: User DAFTAR BARU (Email benar-benar belum ada)
        if mode == 'register' and not user_db:
            role_pilihan = request.session.get('requested_role', 'Supplier')
            user_db = Pengguna(
                username=email_google.split('@')[0],
                email=email_google,
                password_hash="sso_google_account",
                role=role_pilihan
            )
            db.add(user_db)
            db.commit()
            db.refresh(user_db)

        # --- JIKA LOLOS PENGECEKAN, BUAT TOKEN ---
        token_data = {"role": user_db.role, "sub": str(user_db.id_pengguna)}
        access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
        target_dashboard = f"dashboard-{user_db.role.lower()}.html"
        
        return HTMLResponse(content=f"""
            <script>
                localStorage.setItem('token_akses', '{access_token}');
                localStorage.setItem('user_role', '{user_db.role}');
                alert('Berhasil! Selamat datang {user_info.get('name')}');
                window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/{target_dashboard}';
            </script>
        """)

    except Exception as e:
        return HTMLResponse(content=f"<script>alert('Error: {str(e)}'); window.location.href='http://127.0.0.1:5500/frontend-supply-chain/index.html';</script>")
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        email_google = user_info.get("email")
        nama_google = user_info.get("name")

        user_db = db.query(Pengguna).filter(Pengguna.email == email_google).first()
        
        # JIKA USER BELUM ADA -> DAFTARKAN OTOMATIS
        if not user_db:
            role_pilihan = request.session.get('requested_role', 'Supplier')
            user_db = Pengguna(
                username=email_google.split('@')[0], # Buat username dari email
                email=email_google,
                password_hash="sso_google_account", # Penanda login via SSO
                role=role_pilihan
            )
            db.add(user_db)
            db.commit()
            db.refresh(user_db)

        # Buat Token Akses seperti biasa
        token_data = {"role": user_db.role, "sub": str(user_db.id_pengguna)}
        access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

        target_dashboard = f"dashboard-{user_db.role.lower()}.html"
        
        # Script redirect ke Live Server (Sesuaikan path folder kamu)
        html_content = f"""
        <script>
            localStorage.setItem('token_akses', '{access_token}');
            localStorage.setItem('user_role', '{user_db.role}');
            alert('Sukses! Selamat datang di Portal {user_db.role}');
            window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/{target_dashboard}';
        </script>
        """
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"<script>alert('Gagal: {str(e)}'); window.location.href='/';</script>")
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        email_google = user_info.get("email")

        user_db = db.query(Pengguna).filter(Pengguna.email == email_google).first()
        
        if not user_db:
            return HTMLResponse(content="<script>alert('Akses Ditolak: Email tidak terdaftar.'); window.location.href='/';</script>")

        # Buat Token Akses (JWT)
        token_data = {"role": user_db.role, "sub": str(user_db.id_pengguna)}
        access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

        # Redirect otomatis ke Live Server dashboard sesuai Role
        target_dashboard = f"dashboard-{user_db.role.lower()}.html"
        
        html_content = f"""
        <script>
            localStorage.setItem('token_akses', '{access_token}');
            localStorage.setItem('user_role', '{user_db.role}');
            alert('Login Google Berhasil! Selamat datang, {user_info.get('name')}');
            window.location.href = 'http://127.0.0.1:5500/frontend-supply-chain/{target_dashboard}';
        </script>
        """
        return HTMLResponse(content=html_content)
    except Exception as e:
        return HTMLResponse(content=f"<script>alert('Gagal SSO: {str(e)}'); window.location.href='/';</script>")

# --- 4. FITUR 2FA ---
@router.get("/2fa/generate")
def generate_2fa_secret(email: str):
    secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Secure Supply Chain ISA")
    return {
        "pesan": "Masukkan Secret ini ke Google Authenticator Anda",
        "secret_key": secret,
        "qr_code_url": totp_uri
    }

@router.post("/2fa/verify")
def verify_2fa(secret: str, kode_otp: str):
    totp = pyotp.TOTP(secret)
    if totp.verify(kode_otp):
        # Di sini kita buat token dummy untuk testing via Swagger
        token_data = {"role": "Supplier", "sub": "1"} 
        access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
        return {
            "status": "Login Sepenuhnya Berhasil!",
            "access_token": access_token,
            "role": "Supplier"
        }
    raise HTTPException(status_code=401, detail="Kode OTP Salah atau Expired!")