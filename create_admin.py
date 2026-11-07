import pymysql
from getpass import getpass
from werkzeug.security import generate_password_hash
from config import Config

username = input("Enter Admin username: ").strip()
password = getpass("Enter Admin password: ")
confirm_password = getpass("Confirm Admin password: ")

if not username or not password:
    print("Username and password cannot be empty.")
    exit()

if password != confirm_password:
    print("Passwords do not match.")
    exit()

password_hash = generate_password_hash(password)

try:
    connection = pymysql.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )

    with connection.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (%s, %s, 'ADMIN')
            """,
            (username, password_hash)
        )

    connection.commit()
    connection.close()

    print("Admin account created successfully!")

except pymysql.err.IntegrityError:
    print("This username already exists.")

except Exception as e:
    print("Error:", e)