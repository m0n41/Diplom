import uuid
from sqlalchemy.exc import IntegrityError

from app.db.session import SessionLocal
from app.models.models import User, Role, user_role_table
from app.core.security import get_password_hash


def main():
    db = SessionLocal()

    # Ensure admin role exists
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(
            id=uuid.uuid4(),
            name="admin",
            description="Administrator role",
        )
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

    # Ensure admin user exists
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        password_hash = get_password_hash(
            "ChangeMe123"
        )  # замените пароль при необходимости
        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@example.com",
            password_hash=password_hash,
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        print("Создан пользователь admin (логин: admin, пароль: ChangeMe123)")
    else:
        print("Пользователь admin уже существует, создание пропущено.")

    # Привязать роль admin к пользователю, если привязка ещё не существует
    stmt = user_role_table.select().where(
        (user_role_table.c.user_id == admin_user.id)
        & (user_role_table.c.role_id == admin_role.id)
    )
    existing = db.execute(stmt).first()
    if not existing:
        insert_stmt = user_role_table.insert().values(
            user_id=admin_user.id, role_id=admin_role.id
        )
        try:
            db.execute(insert_stmt)
            db.commit()
            print("Роль admin назначена пользователю admin.")
        except IntegrityError:
            db.rollback()
            print("Роль уже была назначена.")
    else:
        print("Роль admin уже назначена пользователю admin.")


if __name__ == "__main__":
    main()
