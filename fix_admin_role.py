import uuid
from app.db.session import SessionLocal
from app.models.models import User, Role, user_role_table


def main():
    db = SessionLocal()

    # Находим пользователя admin
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        print("Пользователь admin не найден!")
        return

    # Находим роль admin
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        print("Роль admin не найдена!")
        return

    # Проверяем, есть ли уже привязка
    existing = (
        db.query(user_role_table)
        .filter(
            user_role_table.c.user_id == admin_user.id,
            user_role_table.c.role_id == admin_role.id,
        )
        .first()
    )

    if existing:
        print("Роль admin уже привязана к пользователю admin.")
    else:
        # Привязываем роль
        db.execute(
            user_role_table.insert().values(
                user_id=admin_user.id, role_id=admin_role.id
            )
        )
        db.commit()
        print("Роль admin успешно привязана к пользователю admin.")


if __name__ == "__main__":
    main()
