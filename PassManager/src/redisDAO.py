import redis
import string
import random

class RedisDAO:
    def __init__(self, host='redis', port=6379, db=0):
        try:
            self.db = redis.Redis(host=host, port=port, db=db)
        except:
            print("Error while connecting with Redis")

    def create_token(self, email):
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        time = 1 * 60
        self.db.set(email, token, time)
        return token

    def get_token(self, email):
        try:
            return self.db.get(email).decode('utf-8')
        except Exception:
            return None


    def create_key_to_reset_password(self, email):
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
        time = 5 * 60
        self.db.set(f"reset{key}", email, time)
        return key

    def get_resetpass_email(self, key):
        try:
            return self.db.get(f"reset{key}").decode('utf-8')
        except Exception:
            return None

    
    def get_time(self, key):
        return self.db.ttl(key)


    def set_user_session(self, sid, user_id, time = 300):
        key = f"sessions:{sid}"
        self.db.set(key, user_id, time)

    def del_user_session(self, sid):
        key = f"sessions:{sid}"
        self.db.delete(key)


    def get_user_id(self, sid):
        key = f"sessions:{sid}"
        if not self.db.exists(key):
            raise Exception("Sesja nie istnieje")
        return self.db.get(key).decode('utf-8')


    def incr_counter_failed_login_attempts(self, user_id):
        key = f"counter_log_attempts:{user_id}"
        self.db.incr(key)
        self.db.expire(key, 360)

    def get_count_login_attempts(self, user_id):
        key = f"counter_log_attempts:{user_id}"
        if self.db.exists(key) == 0:
            return 0
        return self.db.get(key)


    def set_temp_block_user(self, user_id, time):
        key = f"block:{user_id}"
        self.db.set(key, 1, time)

    def del_temp_block_user(self, user_id):
        key = f"block:{user_id}"
        self.db.delete(key)

    def is_user_blocked(self, user_id):
        key = f"block:{user_id}"
        if self.db.exists(key) == 0:
            return False
        else:
            return True

    def get_block_time_user(self, user_id):
        key = f"block:{user_id}"
        if self.db.exists(key) == 0:
            return 0
        return self.get_time(key)


redisDAO = RedisDAO('redis', 6379, 0)