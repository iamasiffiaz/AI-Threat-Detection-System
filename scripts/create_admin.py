"""
Script to create the initial admin user.
Run once after first deployment:
    docker compose exec backend python scripts/create_admin.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal, create_tables
from app.core.security import hash_password
from app.models.user import User, UserRole


async def create_admin():
    await create_tables()

    async with AsyncSessionLocal() as session:
        # Check if admin already exists
        from sqlalchemy import select
        result = await session.execute(select(User).where(User.username == "admin"))
        if result.scalar_one_or_none():
            print("Admin user already exists.")
            return

        admin = User(
            username="admin",
            email="admin@threatdetection.local",
            hashed_password=hash_password("Admin1234!"),
            full_name="System Administrator",
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        print("✅ Admin user created:")
        print("   Username: admin")
        print("   Password: Admin1234!")
        print("   IMPORTANT: Change the password after first login!")


if __name__ == "__main__":
    asyncio.run(create_admin())
