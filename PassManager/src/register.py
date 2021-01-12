from flask import Blueprint, request, make_response, render_template
import string
from src.crypto import hash_password
from src.sqlDAO import sqlDAO_User
import numpy as np
from src.utils import does_string_contain_only_allowed_chars, alert_types


register_page = Blueprint('register_page', __name__, template_folder='templates')

@register_page.route('/register', methods=['GET', 'POST'])
def register():
    mess = "Wprowadź poniżej swoje dane"
    data = init_data()

    if request.method == 'POST':
        try:
            data = read_user_data()
            validate_data(data)
            register_user(data)
            mess = f"Witaj na pokładzie {data['user']}!"
            return render_template('register.html', message=mess, alert_t=alert_types[1], data=data)
        except SamePasswordAndMasterPassException as err:
            return render_template('register.html', message=err, alert_t=alert_types[2], data=data)
        except Exception as err:
            return render_template('register.html', message=err, alert_t=alert_types[2], data=data)

    return render_template('register.html', message=mess, data=data, alert_t = alert_types[0])

def init_data():
    data = {
        'user' : 'username',
        'email' : 'email@mail.com',
        'password' : '',
        'repassword' : '',
        'masterpassword' : '',
        'remasterpassword' : ''
    }
    return data

def read_user_data():
    data = {}
    data['user'] = request.form.get('nickname')
    data['email'] = request.form.get('email')
    data['password'] = request.form.get('password')
    data['repassword'] = request.form.get('repassword')
    data['masterpassword'] = request.form.get('masterpassword')
    data['remasterpassword'] = request.form.get('remasterpassword')
    return data

def validate_data(data):
    allowed = string.ascii_letters + string.digits + "_-"
    condition, c = does_string_contain_only_allowed_chars(data['user'], allowed)
    if not condition:
        raise Exception(f"W nazwie użytkownika znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + "@._"
    condition, c = does_string_contain_only_allowed_chars(data['email'], allowed)
    if not condition:
        raise Exception(f"W podanym emailu znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['password'], allowed)
    if not condition:
        raise Exception(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['repassword'], allowed)
    if not condition:
        raise Exception(f"W podanym master-password znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['masterpassword'], allowed)
    if not condition:
        raise Exception(f"W podanym master-password znalazły się niedozwolone znaki: {c}")

    allowed = string.ascii_letters + string.digits + string.punctuation
    condition, c = does_string_contain_only_allowed_chars(data['remasterpassword'], allowed)
    if not condition:
        raise Exception(f"W podanym haśle znalazły się niedozwolone znaki: {c}")

    if sqlDAO_User.is_exists_user(data['user']):
        raise Exception(f"Użytkownik {data['user']} już istnieje!")

    if sqlDAO_User.is_exists_email(data['email']):
        raise Exception(f"Użytkownik z takim emailem {data['email']} już istnieje!")

    username_constriants(data['user'])
    password_constraints(data['password'])
    password_constraints(data['masterpassword'])

    if data['password'] != data['repassword']:
        raise Exception("Podałeś dwa różne hasła!")

    if data['masterpassword'] != data['remasterpassword']:
        raise Exception("Podałeś dwa różne hasła główne!")

    if data['password'] == data['masterpassword']:
        raise SamePasswordAndMasterPassException()


def register_user(data):
    hash_pass, salt = hash_password(data['password'])
    hash_master_pass, salt_master_pass = hash_password(data['masterpassword'])
    sqlDAO_User.insert_user(data['user'], data['email'], hash_pass, salt, hash_master_pass, salt_master_pass)

def username_constriants(name):
    minLength = 6
    maxLength = 30
    if len(name) < minLength or len(name) > maxLength:
        raise Exception(f"Nazwa użytkownika powinna składać się od {minLength} do {maxLength} znaków")

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


class SamePasswordAndMasterPassException(Exception):
    def __init__(self, message="Master Password nie może być takie samo jak hasło do konta!"):
        self.message = message
        super().__init__(self.message)