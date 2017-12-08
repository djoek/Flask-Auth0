import os
import secrets

from flask import Flask
from flask_auth0 import Auth0

from redis import Redis
from flask_session import RedisSessionInterface

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_bytes(64)
app.permanent_session_lifetime = 86400

app.session_interface = RedisSessionInterface(
    redis=Redis.from_url('redis://redis/0'),
    key_prefix="%s:" % app.name,
    use_signer=True,
)

auth = Auth0(
    base_url=os.getenv('AUTH0_BASE_URL'),
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    # url_prefix="/auth0",
    # session_key="auth0_user",
)
auth.init_app(app)


@app.route('/')
def index():
    return f"Hello, {auth.current_user}"


@app.route('/user')
@auth.login_required()
def user():
    return f"Hello, User {auth.current_user.role} {auth.current_user}"


@app.route('/admin')
@auth.login_required(role="admin")
def admin():
    return f"Hello, Admin {auth.current_user.role} {auth.current_user}"


@app.route('/djoek')
@auth.login_required(nickname="djoek", role="admin")
def djoek():
    return f"Hello, djoek {auth.current_user.role} {auth.current_user}"


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
