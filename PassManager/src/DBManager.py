import time
import mysql.connector

class DBManager:
    def __init__(self, database='db_main', host="db", user="root", password_file=None):
        self.db = None
        self.sql = None
        pf = open(password_file, 'r')
        try:
            self.db = mysql.connector.connect(
                user=user, 
                password=pf.read(),
                host=host,
                database=database,
                auth_plugin='mysql_native_password'
            )
            self.sql = self.db.cursor(buffered=True)
            self.sql.execute("SELECT 1")
            self.sql.fetchall()
        except Exception as err:
            print(f"Error while connecting with DB: host={host}, file={password_file}, err={err}")
            time.sleep(3)
        pf.close()