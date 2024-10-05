from app.db.connection import Base, engine
from app.models import user, friend, message, media

def run_migrations():
    print("Running migrations...")
    Base.metadata.create_all(bind=engine)
    print("Migrations completed.")

if __name__ == "__main__":
    run_migrations()
