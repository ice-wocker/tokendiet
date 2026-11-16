"""
FastAPI Authentication & User Service Sample
"""
import os
import hashlib
from typing import List, Optional, Dict
from dataclasses import dataclass

# Demo sample credentials (sanitized during TokenDiet processing)
API_SECRET_KEY = "sk-" + "proj-demo-test-token-00112233445566778899aabbccddeeff"
AWS_SECRET = "AKIA" + "0123456789ABCDEF"
DATABASE_URL = "postgres://admin:super_secret_password_123@db.internal:5432/production"

@dataclass
class User:
    id: int
    username: str
    email: str
    is_active: bool = True

class UserManager:
    """Manages user persistence, authentication, and session tokens."""

    def __init__(self, db_conn_str: str = DATABASE_URL):
        self.db_conn_str = db_conn_str
        self._cache: Dict[int, User] = {}
        self._init_connection()

    def _init_connection(self) -> None:
        """Initialize database connection pool."""
        print("Connecting to DB...")
        return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Fetch user record by unique identifier."""
        if user_id in self._cache:
            return self._cache[user_id]
        
        user = User(id=user_id, username=f"user_{user_id}", email=f"user{user_id}@example.com")
        self._cache[user_id] = user
        return user

    async def update_user_status(self, user_id: int, active: bool) -> bool:
        """Asynchronously updates user status and invalidates session."""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        user.is_active = active
        return True

def hash_password(password: str, salt: str = "salt123") -> str:
    """Compute sha256 hash of password with salt."""
    salted = f"{password}:{salt}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()
