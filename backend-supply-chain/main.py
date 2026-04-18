from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
from routes import produk, auth, pelacakan 
from starlette.middleware.sessions import SessionMiddleware
import os
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Secure Supply Chain API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Di tahap dev, kita izinkan semua
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "super-rahasia-banget"))
app.include_router(produk.router)
app.include_router(auth.router)
app.include_router(pelacakan.router)

@app.get("/")
def read_root():
    return {"message": "Server Secure Supply Chain API aktif!"}

@app.get("/db-check")
def check_db_connection(db: Session = Depends(get_db)):
    try:
        # Menjalankan query SQL simpel untuk tes
        db.execute(text("SELECT 1"))
        return {"status": "connected", "message": "Database terhubung dengan baik!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Koneksi gagal: {str(e)}")