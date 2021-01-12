from flask import Blueprint
from flask import render_template, request, make_response, url_for, redirect
from src.sqlDAO import sqlDAO_User
from src.redisDAO import redisDAO
from src.utils import alert_types

token_page = Blueprint('token_page', __name__, template_folder='templates')

@token_page.route('/token', methods=['GET', 'POST'])
def token():
    message = request.cookies.get('message')
    alert_t = request.cookies.get('alert_t')
    email = request.cookies.get('email')
    user = request.cookies.get('user')
    if (user is None) or (email is None):
        return redirect(url_for("login_page.login"))

    message = str(message)
    alert_t = str(alert_t)
    email = str(email)
    user = str(user)

    if request.method == 'POST':
        try:
            tokenFromUser = request.form.get('token')
            token = redisDAO.get_token(email)
            if tokenFromUser == token:
                name = request.headers.get('User_Agent')
                sqlDAO_User.insert_device(name, user)
                message = "Token poprawny. Zaloguj się jeszcze raz."
                alert_t = alert_types[1]
                response = make_response('', 303)
                response.set_cookie('message', message, max_age=1*60)
                response.set_cookie('alert_t', alert_t, max_age=1*60)
                response.headers["Location"] = url_for("login_page.login")
                return response
            elif token == None:
                message = "Token wygasł. Zaloguj się jeszcze raz, by otrzymać nowy."
                alert_t = alert_types[0]
                response = make_response('', 303)
                response.set_cookie('message', message, max_age=1*60)
                response.set_cookie('alert_t', alert_t, max_age=1*60)
                response.headers["Location"] = url_for("login_page.login")
                return response
            else:
                message = "Token niepoprawny."
                alert_t = alert_types[3]
        except Exception as err:
            alert_t = alert_types[2]
            message = err

    return render_template('token.html', message=message, alert_t=alert_t)