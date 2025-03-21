import mysql.connector
from mysql.connector import Error, ProgrammingError

try:
    conn = mysql.connector.connect(
        host='127.0.0.1',
        database='db',
        user='root',
        password='poon@psm16828'
    )
    if conn.is_connected():
        print('Connected to database.')
        cursor = conn.cursor()

        tables = ["Users", "Products", "Gaming_PCs", "PC_Specifications",
                  "Game_Performance", "PC_Images", "Parts", "Wishlist"]

        for table_name in tables:
            print(f"\n--- Table: {table_name} ---")
            cursor.execute(f"DESCRIBE {table_name}")
            columns = cursor.fetchall()  # Fetch all rows

            for column in columns:
                print(column)

except Error as e:
    print(f"Error: {e}")
finally:
    if conn.is_connected():
        cursor.close()
        conn.close()
        print("Connection closed.")