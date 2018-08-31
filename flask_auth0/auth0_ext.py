from functools import wraps
from urllib.parse import urlencode
from binascii import hexlify

from secrets import token_bytes as generate_token

import requests
from jose import jwt

from itsdangerous import URLSafeSerializer, BadSignature
from flask import session, abort, redirect, url_for, request, Blueprint, jsonify, g, current_app
from werkzeug.contrib.cache import SimpleCache, BaseCache

from flask_auth0.oidc import OpenIDConfig


class TokenDataDescriptor:

    __slots__ = ['token_name']

    def __init__(self, token_name=None):
        self.token_name = token_name

    def __get__(self, obj, _type=None):
        if _type is not None:
            return g.token_data.get(self.token_name)

    def __set_name__(self, owner, name):
        if self.token_name is None:
            self.token_name = name


# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


class AuthorizationCodeFlow(object):

    def __init__(self, app=None,
                 *,
                 base_url=None,
                 client_id=None, client_secret=None,
                 cache=None,
                 scope='openid',
                 url_prefix='/oauth2', uid_key='auth0'):

        self.app = app

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.url_prefix = url_prefix
        self.uid_key_in_session = uid_key

        # Setup backend cache
        if cache is None:
            self.cache = SimpleCache()
        elif isinstance(cache, BaseCache):
            self.cache = cache
        else:
            raise ValueError("your backend cache must implement werkzeug.contrib.cache.BaseCache")

        self.signer = None
        self.openid_config = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        # Config
        self.client_id = app.config.setdefault('AUTH0_CLIENT_ID', self.client_id)
        self.client_secret = app.config.setdefault('AUTH0_CLIENT_SECRET', self.client_secret)
        self.base_url = app.config.setdefault('AUTH0_BASE_URL', self.base_url)
        self.uid_key_in_session = app.config.setdefault('AUTH0_SESSION_KEY', self.uid_key_in_session)

        if any(v is None for v in (self.client_id, self.client_secret, self.base_url)):
            raise ValueError("Missing Config Variables")

        self.url_prefix = app.config.setdefault('AUTH0_URL_PREFIX', self.url_prefix)
        self.scope = app.config.setdefault('AUTH0_SCOPE', self.scope)

        # Utils
        self.signer = URLSafeSerializer(app.secret_key)
        self.openid_config = OpenIDConfig(self.base_url)

        # Routes
        blueprint = Blueprint('flask-auth0', __name__)

        blueprint.add_url_rule('/login', 'login', self.login)
        blueprint.add_url_rule('/logout', 'logout', self.logout)
        blueprint.add_url_rule('/callback', 'callback', self.callback)

        blueprint.errorhandler(AuthError)(self.handle_auth_error)
        blueprint.before_app_request(self.get_user_auth_data)

        app.register_blueprint(blueprint=blueprint, url_prefix=self.url_prefix)

    @staticmethod
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response

    def login_required(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if self.is_authenticated:
                return f(*args, **kwargs)
            return abort(401)
        return decorated_function

    def get_user_auth_data(self):
        g.uid = session.get(self.uid_key_in_session)
        if g.uid is not None:
            g.token_data = self.cache.get(f"{g.uid}:token_data") or {}
        else:
            g.token_data = {}

    @property
    def is_authenticated(self):
        return g.uid is not None and self.cache.has(f"{g.uid}:token_data")

    token_type = TokenDataDescriptor()
    access_token = TokenDataDescriptor()
    refresh_token = TokenDataDescriptor()
    claims = TokenDataDescriptor()

    @property
    def sub(self):
        return self.claims.get('sub') if self.claims else None

    @property
    def authorization_header(self):
        return f"{self.token_type} {self.access_token}"

    def verify_claims(self, id_token):

        # We can get the info in the id_token, but it needs to be verified
        u_header, u_claims = jwt.get_unverified_header(id_token), jwt.get_unverified_claims(id_token)
        # Get the key which was used to sign this id_token
        kid, alg = u_header['kid'], u_header['alg']

        # Obtain JWT and the keys to validate the signature
        jwks_response = requests.get(self.openid_config.jwks_uri).json()
        for key in jwks_response['keys']:
            if key['kid'] == kid:
                try:
                    payload = jwt.decode(
                        token=id_token, key=key,
                        audience=self.client_id,
                        issuer=self.openid_config.issuer)
                except jwt.ExpiredSignatureError:
                    raise AuthError({"code": "token_expired",
                                     "description": "token is expired"}, 401)
                except jwt.JWTClaimsError:
                    raise AuthError({"code": "invalid_claims",
                                     "description":
                                         "incorrect claims,"
                                         "please check the audience and issuer"}, 401)
                except Exception:
                    raise AuthError({"code": "invalid_header",
                                     "description": "Unable to parse authentication token."}, 401)
                else:
                    return payload

        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)

    def get_user_info(self):
        try:
            result = requests.get(
                self.openid_config.userinfo_url,
                headers={
                    'Authorization': self.authorization_header,
                    'Content-Type': 'application/json'
                }
            )
            result.raise_for_status()
        except requests.HTTPError:
            raise
        else:
            return result.json()

    def logout(self):
        """
        Handler for logging out a user.
        This clears the server-side session entry and redirects to the index endpoint
        :return: redirect()
        """
        # Clear the cached tokens server-side
        self.cache.delete(f"{g.uid}:token_data")
        
        # Clear the session
        session.clear()
        
        # Redirect to auth0 logout
        params = {
            'returnTo': url_for('index', _external=True),
            'client_id': self.client_id
        }
        return redirect(self.openid_config.issuer + 'v2/logout?' + urlencode(params))

    def login(self):
        """
        Handler for logging in a user.
        This provides a redirect to the authorization url
        :return: redirect()
        """

        state = self.signer.dumps({'return_to': request.referrer or '/'})

        query_parameters = urlencode({
            'response_type': 'code',
            'scope': self.scope,
            'state': state,
            'client_id': self.client_id,
            'redirect_uri': url_for('flask-auth0.callback', _external=True)
        })
        return redirect(
            f"{self.openid_config.authorization_url}?{query_parameters}"
        )

    def refresh(self):
        token_result = requests.post(
            url=self.openid_config.token_url,
            headers={
                'Content-Type': 'application/json'
            },
            json={
                'grant_type': 'refresh_token',
                'scope': self.scope,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': self.refresh_token
            }
        )
        token_result.raise_for_status()

        token_data = token_result.json()
        self._update_tokens(**token_data)

    def callback(self):
        """
        Handler for the OAuth2 callback
        This gets the code and turns it into tokens
        :return: redirect()
        """
        # try to login using the code in the url arg
        code = request.args.get('code')
        if code:

            try:  # to get the state
                state = self.signer.loads(request.args.get('state'))
            except BadSignature:  # State has been tampered with
                current_app.logger.info(request.args.get('state'))
                return abort(401)
            else:
                return_to = state.get('return_to', current_app.config.get('APPLICATION_ROOT'))

            token_result = requests.post(
                self.openid_config.token_url,
                data={
                    'code': code,
                    'grant_type': 'authorization_code',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'redirect_uri': url_for('flask-auth0.callback', _external=True)
                })
            token_result.raise_for_status()
            token_data = token_result.json()

            g.uid = session.setdefault(
                self.uid_key_in_session,
                hexlify(generate_token(64)).decode('ascii'))

            if 'error' in g.token_data:
                raise AuthError
            else:
                self._update_tokens(**token_data)
                return redirect(return_to)

        return abort(401)

    def _update_tokens(self, *,
                       access_token, token_type="Bearer",
                       refresh_token=None,
                       id_token=None,
                       expires_in=86400, **kwargs):

        # explicitly passing id_token here because it's not yet in self
        claims = self.verify_claims(id_token)
        g.token_data = {
            'token_type': token_type,
            'access_token': access_token,
            'refresh_token': refresh_token,
            'claims': claims,
        }

        self.cache.set(
            f"{g.uid}:token_data", g.token_data, timeout=expires_in)
