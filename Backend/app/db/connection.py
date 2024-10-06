from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# app/db/connection.py
from sqlalchemy.orm import declarative_base

Base = declarative_base()


# Database connection settings (replace with your actual DB settings)
DATABASE_URL = "postgresql://user:password@localhost/db_name"

# Create a new database engine
engine = create_engine(DATABASE_URL)

# Create a sessionmaker bound to the engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get the DB session for FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
