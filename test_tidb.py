
import os
import ssl
import pymysql
from dotenv import load_dotenv

load_dotenv()

# Load the TiDB CA certificate
ca_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.getenv("TIDB_SSL_CA")
)

ssl_context = ssl.create_default_context(cafile=ca_path)

try:
    connection = pymysql.connect(
        host=os.getenv("TIDB_HOST"),
        port=int(os.getenv("TIDB_PORT", "4000")),
        user=os.getenv("TIDB_USER"),
        password=os.getenv("TIDB_PASSWORD"),
        database="sys",
        ssl=ssl_context,
        connect_timeout=15
    )

    print("Successfully connected to TiDB!")

    with connection.cursor() as cursor:
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print("TiDB Version:", version[0])

        cursor.execute("CREATE DATABASE IF NOT EXISTS gdms")
        print("GDMS database created or already exists!")

    connection.close()
    print("Connection closed successfully.")

except Exception as e:
    print("Connection failed.")
    print("Error:", e)
