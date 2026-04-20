import hashlib 
import json
from datetime import datetime 

def generate_hash(id_log: int, aksi_pelacakan: str, waktu_log: datetime, hash_sebelumnya: str) -> str:
    # FORMAT WAKTU: Buang milidetik agar konsisten saat keluar-masuk database
    waktu_string = waktu_log.strftime('%Y-%m-%d %H:%M:%S')
    
    # Gunakan waktu_string yang sudah diformat
    data_string = f"{id_log}-{aksi_pelacakan}-{waktu_string}-{hash_sebelumnya}"
    hash_object = hashlib.sha256(data_string.encode('utf-8'))
    return hash_object.hexdigest()

def verify_chain(logs: list) -> bool:
    for i in range(1, len(logs)):
        current_log = logs[i]
        previous_log = logs[i-1]

        if current_log.hash_sebelumnya != previous_log.hash_sekarang:
            return False
        
        recalculated_hash = generate_hash (
            current_log.id_log,
            current_log.aksi_pelacakan,
            current_log.waktu_log,
            current_log.hash_sebelumnya
        )

        if current_log.hash_sekarang != recalculated_hash:
            return False 
        
    return True