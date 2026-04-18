from fastapi import HTTPException, Depends, Request
from jose import jwt, JWTError
import os

SECRET_KEY = os.getenv("SECRET_KEY", "super-rahasia-banget")
ALGORITHM = "HS256"

def get_current_user_role(request: Request):
    # Mengambil token dari header 'Authorization: Bearer <token>'
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Anda belum login!")
    
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("role")
    except (JWTError, IndexError):
        raise HTTPException(status_code=401, detail="Token tidak valid!")

def role_required(allowed_roles: list):
    """
    Decorator untuk membatasi akses berdasarkan list role yang diizinkan.
    """
    def decorator(role: str = Depends(get_current_user_role)):
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Akses Ditolak: Role Anda tidak diizinkan.")
        return role
    return decorator