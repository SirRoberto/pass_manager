from flask import Flask
from flask import render_template, redirect, url_for
from flask_wtf import CSRFProtect
from src.register import register_page
from src.login import login_page
from src.passmanager import passmanager_page
from src.token_auth import token_page
import os


app = Flask(__name__)
app.config.update(
    SECRET_KEY = os.urandom(64),
    SESSION_COOKIE_SECURE = True,
    REMEMBER_COOKIE_SECURE = True,
    SESSION_COOKIE_HTTPONLY = True,
    REMEMBER_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
)

csrf = CSRFProtect(app)

app.register_blueprint(register_page)
app.register_blueprint(login_page)
app.register_blueprint(passmanager_page)
app.register_blueprint(token_page)

@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy']="default-src 'self'"
    #resp.headers['X-Content-Type-Options'] = 'nosniff'
    #resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    #resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp


@app.route('/')
def index():
    return redirect(url_for('welcome'))


@app.route('/welcome')
def welcome():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)