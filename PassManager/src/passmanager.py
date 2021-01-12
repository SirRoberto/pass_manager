from flask import Blueprint, render_template, request, make_response
from flask.globals import session
from flask.helpers import url_for
from werkzeug.utils import redirect, validate_arguments
from src.sqlDAO import sqlDAO_User
from src.redisDAO import redisDAO
from src.crypto import verify_password, create_key, encrypt_password, decrypt_password
from src.utils import alert_types, does_string_contain_only_allowed_chars
import string

passmanager_page = Blueprint('passmanager_page', __name__, template_folder='templates')

@passmanager_page.route('/passmanager', methods=['GET', 'POST'])
def passmanager():
    try:
        user_data = init_data()
        passwords_list = init_passwords_list(user_data['uid'])
        devices = sqlDAO_User.get_devices_list(user_data['uid'])
        message = f"Witaj {user_data['username']}!"
        alert_t = alert_types[1]
    except SessionDoesNotExistException as err:
        response = make_response('', 303)
        message = err.message
        response.set_cookie('message', message, max_age=1*60)
        response.set_cookie('alert_t', alert_types[2], max_age=1*60)
        response.headers["Location"] = url_for("login_page.login")
        return response
    except Exception:
        return redirect(url_for('login_page.login'))

    if request.method == 'POST':
        try:
            if request.form['addButton'] == 'Dodaj':
                new_pass_data = read_data_from_add_pass()
                try:
                    validate_new_pass_data(new_pass_data)
                    save_password(user_data, new_pass_data)
                    message = "Hasło zostało dodane pomyślnie!"
                    alert_t = alert_types[1]
                    return redirect(url_for('passmanager_page.passmanager'))
                except InvalidDataException as err:
                    message = err.message
                    alert_t = alert_types[2]
                except Exception as err:
                    message = err
                    alert_t = alert_types[2]
                return render_template('passmanager.html', message=message, alert_t=alert_t, passwords=passwords_list, devices=devices)
        except Exception:
            pass
            
        for i in range(0, len(passwords_list)):
            try:
                if request.form[f'showButton{i}'] == 'Pokaż':
                    try:
                        m_pass = request.form[f'masterpass{i}']
                        validate_master_pass(m_pass, user_data)
                        passwords_list = show_password(i, passwords_list, m_pass, user_data)
                        message = i
                        alert_t = alert_types[1]
                    except Exception as err:
                        return render_template('passmanager.html', message=err, alert_t=alert_types[3], passwords=passwords_list, devices=devices)
            except Exception:
                pass

        try:
            if request.form['logoutButton'] == 'Wyloguj się':
                log_out(user_data['sid'])
                return redirect(url_for('passmanager_page.passmanager'))
        except Exception:
            pass

    return render_template('passmanager.html', message=message, alert_t=alert_t, passwords=passwords_list, devices=devices)


def init_data():
    data = {}
    data['sid'] = session['sid']
    data['role'] = session['role']
    does_exist_session(data['sid'])
    data['uid'] = redisDAO.get_user_id(data['sid'])
    data['username'] = sqlDAO_User.get_user_name(data['uid'])
    return data


def read_data_from_add_pass():
    data = {}
    data['nameservice'] = request.form.get('nameservice')
    data['newpassword'] = request.form.get('newpassword')
    data['renewpassword'] = request.form.get('renewpassword')
    data['masterpassword'] = request.form.get('masterpassword')
    return data


def init_passwords_list(uid):
    pass_list = []
    names_l = sqlDAO_User.get_servicename_list(uid)
    for n in names_l:
        item = {}
        item['id'] = n[0]
        item['name'] = n[1]
        item['password'] = '***************'
        item['out_type'] = 'password'
        pass_list.append(item)
    return pass_list


def validate_new_pass_data(data):
    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['nameservice'], allowed)
    if not condition:
        raise InvalidDataException(f"W nazwie serwisu/URL znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['newpassword'], allowed)
    if not condition:
        raise InvalidDataException(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['renewpassword'], allowed)
    if not condition:
        raise InvalidDataException(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    if data['newpassword'] != data['renewpassword']:
        raise Exception("Podałeś dwa różne hasła!")


def validate_master_pass(m_pass, user_data):
    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(m_pass, allowed)
    if not condition:
        raise InvalidDataException(f"W nazwie serwisu/URL znalazły się niedozwolone znaki: {c}")

    hash_master_password, salt = sqlDAO_User.get_master_password_and_salt(user_data['uid'])
    if not verify_password(m_pass, hash_master_password, salt):
        raise Exception("Błędne hasło główne!")


def show_password(indeks, pass_list, m_pass, user_data):
    id_pass = pass_list[indeks]['id']
    print(id_pass)
    encrypted = sqlDAO_User.get_password(id_pass)

    _, salt = sqlDAO_User.get_master_password_and_salt(user_data['uid'])

    key = create_key(m_pass, salt)
    nonce = get_nonce(user_data['uid'])
    decrypted = decrypt_password(key, encrypted, nonce)
    
    pass_list[indeks]['password'] = decrypted
    pass_list[indeks]['out_type'] = 'text'
    return pass_list



def save_password(user_data, pass_data):
    hash_master_password, salt = sqlDAO_User.get_master_password_and_salt(user_data['uid'])
    if not verify_password(pass_data['masterpassword'], hash_master_password, salt):
        raise Exception("Błędne hasło główne!")

    key = create_key(pass_data['masterpassword'], salt)
    nonce = get_nonce(user_data['uid'])
    encrypted = encrypt_password(key, pass_data['newpassword'], nonce)
    sqlDAO_User.add_password(pass_data['nameservice'], encrypted, user_data['uid'])


def get_nonce(uid):
    _, nonce = sqlDAO_User.get_master_password_and_salt(uid)
    return nonce[-16:]


def does_exist_session(sid):
    try:
        redisDAO.get_user_id(sid)
    except Exception:
        raise SessionDoesNotExistException()


def log_out(sid):
    redisDAO.del_user_session(sid)


class SessionDoesNotExistException(Exception):
    def __init__(self, message="Sesja wygasła"):
        self.message = message
        super().__init__(self.message)

class InvalidDataException(Exception):
    def __init__(self, message="Dane są niepoprawne"):
        self.message = message
        super().__init__(self.message)