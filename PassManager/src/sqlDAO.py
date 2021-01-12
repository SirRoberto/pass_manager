from src.DBManager import DBManager

class SQLDAO:
    def __init__(self, user, host, database, password):
        self.db = None
        self.sql = None
        while (self.db is None) or (self.sql is None):
            dbManager = DBManager(database=database, host=host, user=user, password_file=password)
            self.db = dbManager.db
            self.sql = dbManager.sql

    def is_exists_user(self, name):
        self.sql.execute("""SELECT 1 FROM users
                            WHERE name=%(name)s""",
                            {'name':name}
        )
        count = self.sql.rowcount
        return False if count==0 else True

    def is_exists_email(self, email):
        self.sql.execute("""SELECT 1 FROM users
                            WHERE email=%(email)s""",
                            {'email':email}
        )
        count = self.sql.rowcount
        return False if count==0 else True

    def insert_user(self, name, email, password, salt, master_password, hash_salt_password):
        self.sql.execute("""INSERT INTO users (name, email, login_pass, login_salt) VALUES
                        ( %(username)s, %(email)s, %(pass)s, %(salt)s)""",
                        {'username':name, 'email':email, 'pass':password, 'salt':salt}
        )
        uid = self.sql._last_insert_id
        self.sql.execute("""INSERT INTO master_passwords (master_pass, master_salt, user_id) VALUES
                        ( %(pass)s, %(salt)s, %(uid)s)""",
                        {'pass':master_password, 'salt':hash_salt_password, 'uid':uid}
        )
        self.db.commit()

    def add_password(self, servicename, password, user_id):
        self.sql.execute("""INSERT INTO passwords (pass, name, user_id) VALUES
                        ( %(pass)s, %(name)s, %(uid)s)""",
                        {'pass':password, 'name':servicename, 'uid':user_id}
        )
        self.db.commit()

    def get_servicename_list(self, user_id):
        self.sql.execute("""SELECT id, name FROM passwords
                            WHERE user_id = %(uid)s
                            ORDER BY id DESC""",
                        {'uid':user_id}
        )
        try:
            result = self.sql.fetchall()
            result_l = [[item[0], item[1]] for item in result]
            return result_l
        except Exception:
            raise Exception("Użytkownik o takiej nazwie nie istnieje")

    def get_password(self, pass_id):
        self.sql.execute("""SELECT pass FROM passwords
                            WHERE id = %(id)s
                            ORDER BY id DESC""",
                        {'id':pass_id}
        )
        try:
            result = self.sql.fetchone()
            return result[0]
        except Exception:
            raise Exception("Hasło nie istniejee")

    def get_login_password_and_salt(self, name):
        self.sql.execute("""SELECT login_pass, login_salt FROM users
                            WHERE name = %(username)s
                            ORDER BY id DESC""",
                        {'username':name}
        )
        try:
            result = self.sql.fetchone()
            return result[0], result[1]
        except Exception:
            raise Exception("Użytkownik o takiej nazwie nie istnieje")

    def get_master_password_and_salt(self, user_id):
        self.sql.execute("""SELECT master_pass, master_salt FROM master_passwords
                            WHERE user_id = %(uid)s
                            ORDER BY id DESC""",
                        {'uid':user_id}
        )
        try:
            result = self.sql.fetchone()
            return result[0], result[1]
        except Exception:
            raise Exception("Użytkownik o takiej nazwie nie istnieje")


    def get_user_id(self, name):
        self.sql.execute("""SELECT id FROM users
                            WHERE name=%(name)s""",
                            {'name':name}
        )
        try:
            result = self.sql.fetchone()
            return result[0]
        except Exception:
            raise Exception("Użytkownik o takiej nazwie nie istnieje")

    def get_user_name(self, id):
        self.sql.execute("""SELECT name FROM users
                            WHERE id=%(id)s""",
                            {'id':id}
        )
        try:
            result = self.sql.fetchone()
            return result[0]
        except Exception:
            raise Exception("Użytkownik o takim id nie istnieje")

    def get_email(self, name):
        self.sql.execute("""SELECT email FROM users
                            WHERE name=%(name)s""",
                            {'name':name}
        )
        try:
            result = self.sql.fetchone()
            return result[0]
        except Exception:
            raise Exception("Użytkownik o takiej nazwie nie istnieje")

    def is_exists_device(self, name):
        self.sql.execute("""SELECT 1 FROM devices
                            WHERE name=%(name)s""",
                            {'name':name}
        )
        count = self.sql.rowcount
        return False if count==0 else True

    def insert_device(self, name, username):
        uid = self.get_user_id(username)
        self.sql.execute("""INSERT INTO devices (name, user_id) VALUES
                        ( %(name)s, %(uid)s )""",
                        {'name':name, 'uid':uid }
        )
        self.db.commit()

    def get_device_id(self, name):
        self.sql.execute("""SELECT id FROM devices
                            WHERE name=%(name)s""",
                            {'name':name}
        )
        try:
            result = self.sql.fetchone()
            return result[0]
        except Exception:
            raise Exception("User_Agent o takiej nazwie nie istnieje")

    def get_devices_list(self, user_id):
        self.sql.execute("""SELECT name FROM devices
                            WHERE user_id = %(uid)s
                            ORDER BY id DESC""",
                        {'uid':user_id}
        )
        try:
            result = self.sql.fetchall()
            result_l = [item[0] for item in result]
            return result_l
        except Exception:
            raise Exception("Użytkownik o takim id nie istnieje")


sqlDAO_User = SQLDAO(user='passmanagerUser', host='db', database='db_passmanager', password='/run/secrets/db-password')
