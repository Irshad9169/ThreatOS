"""
models/base.py
──────────────
Single declarative base shared by every ORM model.
All models import Base from here — never redeclare it.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide SQLAlchemy declarative base."""
    pass
