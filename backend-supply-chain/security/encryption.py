from cryptography.fernet import Fernet
import os 
from dotenv import load_dotenv

load_dotenv()
""" Generate dummy aja ini """
SECRET_KEY = os.getenv("SECRET_KEY", Fernet.generate_key().decode()).encode()

cipher_suite = Fernet(SECRET_KEY)

def encrypt_data(text:str) -> str:
    if not text:
        return ""
    
    cipher_text = cipher_suite.encrypt(text.encode('utf-8'))
    return cipher_text.decode('utf-8')

def decrypt_data(cipher_text:str) -> str:
    if not cipher_text:
        return ""
    
    plain_text = cipher_suite.decrypt(cipher_text.encode('utf-8'))
    return plain_text.decode('utf-8')

