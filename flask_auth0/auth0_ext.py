from functools import wraps

from flask import session, abort
from itsdangerous import URLSafeSerializer

from flask_auth0.oidc import OpenIDConfig
from flask_auth0.blueprint import auth0


class Auth0(object):

    def __init__(self, app=None, *,
                 base_url=None, client_id=None, client_secret=None,
                 url_prefix="/auth", session_key="auth0_user"):
        self.app = app

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.url_prefix = url_prefix
        self.session_key = session_key

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.client_id = app.config.setdefault('AUTH0_CLIENT_ID', self.client_id)
        self.client_secret = app.config.setdefault('AUTH0_CLIENT_SECRET', self.client_secret)
        self.base_url = app.config.setdefault('AUTH0_BASE_URL', self.base_url)
        self.session_key = app.config.setdefault('AUTH0_SESSION_KEY', self.session_key)

        app.auth0_signer = URLSafeSerializer(app.secret_key)
        app.auth0_oidc = OpenIDConfig(self.base_url)

        app.register_blueprint(auth0, url_prefix=self.url_prefix)

    def login_required(self, **match_fields):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                user_instance = self.current_user
                if user_instance \
                        and user_instance.is_authenticated \
                        and all(getattr(user_instance, key, None) == value
                                for key, value in match_fields.items()):
                    return f(*args, **kwargs)
                return abort(401)

            return decorated_function
        return decorator

    @property
    def current_user(self):
        return session.get(self.session_key)
