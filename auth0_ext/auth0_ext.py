from functools import wraps

from flask import session, abort
from itsdangerous import URLSafeSerializer

from auth0_ext.oidc import OpenIDConfig
from auth0_ext.blueprint import auth0


class Auth0(object):

    def __init__(self, app=None, *, base_url=None, client_id=None, client_secret=None, url_prefix="/auth"):
        self.app = app

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.url_prefix = url_prefix

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        client_id = app.config.setdefault('AUTH0_CLIENT_ID', self.client_id)
        client_secret = app.config.setdefault('AUTH0_CLIENT_SECRET', self.client_secret)
        base_url = app.config.setdefault('AUTH0_BASE_URL', self.base_url)

        app.auth0_signer = URLSafeSerializer(app.secret_key)
        app.auth0_oidc = OpenIDConfig(base_url)

        app.register_blueprint(auth0, url_prefix=self.url_prefix)

    def login_required(self, **match_fields):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                user_instance = self.current_user
                if user_instance and all(getattr(user_instance, key, None) == value
                                         for key, value in match_fields.items()):
                    return f(*args, **kwargs)
                return abort(401)

            return decorated_function
        return decorator

    @property
    def current_user(self):
        return session.get('auth0_user')
