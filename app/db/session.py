from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings

# Create SQLAlchemy engine
engine = create_engine(
    str(
        settings.POSTGRES_DSN
    ),  # Convert PostgresDsn object to plain string for SQLAlchemy
    echo=settings.DATABASE_ECHO,
    poolclass=NullPool,  # Simple pooling suitable for short-lived processes
    future=True,
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def get_db():
    """
    FastAPI dependency that provides a SQLAlchemy session.
    Yields the session and ensures it is closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
