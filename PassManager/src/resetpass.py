from flask import Blueprint
from flask import render_template, request, make_response, url_for, redirect
from src.sqlDAO import sqlDAO_User
from src.redisDAO import redisDAO
from src.utils import alert_types
from src.utils import does_string_contain_only_allowed_chars
from src.crypto import hash_password
import string
import numpy as np

resetpass_page = Blueprint('resetpass_page', __name__, template_folder='templates')

@resetpass_page.route('/resetpass/<string:key>', methods=['GET', 'POST'])
def resetpass(key):
    email = redisDAO.get_resetpass_email(key)
    if email is None:
        return redirect(url_for('login_page.login'))
    message = f"Wypełnij formularz nowymi danymi"
    alert_t = alert_types[0]

    if request.method == 'POST':
        try:
            data = read_data()
            data['email'] = email
            data['uid'] = sqlDAO_User.get_user_id_by_email(email)
            validate_data(data)
            change_password(data)
            if redisDAO.is_user_blocked(data['uid']):
                redisDAO.del_temp_block_user(data['uid'])
            message = "Hasło zostało zmienione!"
            alert_t = alert_types[1]
            response = make_response('', 303)
            response.set_cookie('message', message, max_age=1*60)
            response.set_cookie('alert_t', alert_t, max_age=1*60)
            response.headers["Location"] = url_for("login_page.login")
            return response
        except Exception as err:
            message = err
            alert_t = alert_types[2]

    return render_template('resetpass.html', message=message, alert_t=alert_t)


def read_data():
    data = {}
    data['password'] = request.form.get('password')
    data['repassword'] = request.form.get('repassword')
    return data


def validate_data(data):
    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['password'], allowed)
    if not condition:
        raise Exception(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['repassword'], allowed)
    if not condition:
        raise Exception(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    if not sqlDAO_User.is_exists_email(data['email']):
        raise Exception(f"Użytkownik z takim emailem nie istnieje!")

    password_constraints(data['password'])

    if data['password'] != data['repassword']:
        raise Exception("Podałeś dwa różne hasła!")


def change_password(data):
    hash_pass, salt = hash_password(data['password'])
    sqlDAO_User.update_login_password(data['email'], hash_pass, salt)


def password_constraints(password):
    min_nLowercases = 1
    min_nUppercases = 1
    min_nDigits = 1
    min_nPunctuations = 1
    length = 8
    if len(password) < length:
        raise Exception(f"Hasło powinno składać się z conajmniej {length} znaków!")
    nLowercases = np.sum([c in string.ascii_lowercase for c in password])
    if nLowercases < min_nLowercases:
        raise Exception(f"Hasło powinno zawierać conajmniej {min_nLowercases} małą literę!")
    nUppercases = np.sum([c in string.ascii_uppercase for c in password])
    if nUppercases < min_nUppercases:
        raise Exception(f"Hasło powinno zawierać conajmniej {min_nUppercases} wielką literę!")
    nDigits = np.sum([c in string.digits for c in password])
    if nDigits < min_nDigits:
        raise Exception(f"Hasło powinno zawierać conajmniej {min_nDigits} cyfrę!")
    nPunctuations = np.sum([c in string.punctuation for c in password])
    if nPunctuations < min_nPunctuations:
        raise Exception(f"Hasło powinno zawierać conajmniej {min_nPunctuations} znak specjalny!")