from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base 
import os
from dotenv import load_dotenv 

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DB_URL", "mysql+pymysql://root:@localhost:3306/supply_chain_db")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
Sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = Sessionlocal()
    try: 
        yield db
    finally: 
        db.close()