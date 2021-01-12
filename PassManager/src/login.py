from flask import Blueprint
from flask import render_template, request, make_response, url_for, session
from src.sqlDAO import sqlDAO_User
from src.redisDAO import redisDAO
from src.crypto import verify_password
import string
import random
from src.utils import alert_types, does_string_contain_only_allowed_chars

login_page = Blueprint('login_page', __name__, template_folder='templates')


@login_page.route('/login', methods=['GET', 'POST'])
def login():
    message = request.cookies.get('message')
    alert_t = request.cookies.get('alert_t')
    if (message is None) or (alert_t is None):
        message = "Podaj swoje dane"
        alert_t = alert_types[0]
    data = init_data()

    if request.method == 'POST':
        try:
            data = read_user_data()
            validate_data(data)
            if is_user_blocked(data['user']):
                raise UserIsBlockedException()
            authenticate(data['user'], data['password'], data['device'])
            response = authorize(data['user'])
            return response
        except InvalidDataException as err:
            message=err
            alert_t=alert_types[2]
        except WrongUsernameException:
            message = "Dane logowania są niepoprawne"
            alert_t=alert_types[2]
        except WrongPasswordException:
            uid = sqlDAO_User.get_user_id(data['user'])
            redisDAO.incr_counter_failed_login_attempts(uid)
            verify_login_attempts(uid)
            err = "Dane logowania są niepoprawne"
            alert_t = alert_types[2]
            if get_block_time_user(uid) != '0':
                err += f"\n Konto użytkownika zostało zablokowane na {get_block_time_user(uid)} sekund"
                alert_t = alert_types[3]
            message = err
        except NewDeviceException as err:
            response = authenticate_by_token(data['user'], err)
            return response
        except UserIsBlockedException:
            uid = sqlDAO_User.get_user_id(data['user'])
            message = f"Konto użytkownika zostało zablokowane na {get_block_time_user(uid)} sekund"
            alert_t = alert_types[3]

    return render_template('login.html', message=message, alert_t=alert_t, data=data)


def init_data():
    data = {
        'user' : '',
        'email' : '',
        'password' : '',
        'device' : ''
    }
    return data


def read_user_data():
    data = {}
    data['user'] = request.form.get('nickname')
    data['password'] = request.form.get('password')
    data['device'] = request.headers.get('User-Agent')
    return data


def validate_data(data):
    allowed = string.ascii_letters + string.digits + "_-"
    condition, c = does_string_contain_only_allowed_chars(data['user'], allowed)
    if not condition:
        raise InvalidDataException(f"W nazwie użytkownika znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['password'], allowed)
    if not condition:
        raise InvalidDataException(f"W podanym haśle znalazły się niedozwolone znaki: {c}")


def is_user_blocked(user):
    try:
        uid = sqlDAO_User.get_user_id(user)
    except Exception:
        raise WrongUsernameException()

    return redisDAO.is_user_blocked(uid)

def verify_login_attempts(uid):
    attempts = int(redisDAO.get_count_login_attempts(uid))
    if attempts < 5:
        return False
    elif attempts < 10:
        redisDAO.set_temp_block_user(uid, 5 * 60)
    else:
        redisDAO.set_temp_block_user(uid, 60*60)

def get_block_time_user(uid):
    return str(redisDAO.get_block_time_user(uid))
    

def authenticate(username, password, device):
    try:
        hash_pass, salt = sqlDAO_User.get_login_password_and_salt(username)
    except Exception:
        raise WrongUsernameException()

    if not verify_password(password, hash_pass, salt):
        raise WrongPasswordException()

    if not sqlDAO_User.is_exists_device(device):
        raise NewDeviceException(device=device)
        

def authorize(username):
    session_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=64))
    uid = sqlDAO_User.get_user_id(username)
    redisDAO.set_user_session(sid=session_id, user_id=uid)
    session['sid'] = session_id
    session['role'] = "user"
    response = make_response('', 303)
    response.headers["Location"] = url_for("passmanager_page.passmanager")
    return response


def authenticate_by_token(username, err):
    email = sqlDAO_User.get_email(username)
    token = redisDAO.create_token(email)
    send_token_by_email(token, email)
    alert_t = alert_types[0]
    response = make_response('', 303)
    response.set_cookie('email', email, max_age=2*60, httponly=True, secure=True, samesite='Lax')
    response.set_cookie('user', username, max_age=2*60, httponly=True, secure=True, samesite='Lax')
    email = f'{email[:3]}***@***{email[-3:]}'
    message = err.message + f". Token autoryzacyjny został wysłany na twój e-mail: {email}. Wpisz go poniżej."
    response.set_cookie('message', message, max_age=1*60)
    response.set_cookie('alert_t', alert_t, max_age=1*60)
    response.headers["Location"] = url_for("token_page.token")
    return response

def send_token_by_email(token, email):
    print(f"\n{email} twój token to: \n{token}\n")



class NewDeviceException(Exception):
    def __init__(self, message="Logujesz się z nowego urządzenia", device='device'):
        self.device = device
        self.message = message
        super().__init__(self.message)

class InvalidDataException(Exception):
    def __init__(self, message="Dane są niepoprawne"):
        self.message = message
        super().__init__(self.message)

class WrongPasswordException(Exception):
    def __init__(self, message="Błędne hasło"):
        self.message = message
        super().__init__(self.message)

class WrongUsernameException(Exception):
    def __init__(self, message="Błędna nazwa użytkownika"):
        self.message = message
        super().__init__(self.message)

class UserIsBlockedException(Exception):
    def __init__(self, message="Użytkownik jest zablokowany"):
        self.message = message
        super().__init__(self.message)