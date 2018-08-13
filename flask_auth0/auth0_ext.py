from functools import wraps
from urllib.parse import urlencode
from binascii import hexlify

try:  # py3.6
    from secrets import token_bytes as generate_token
except ImportError:  # older
    from os import urandom as generate_token

import requests
from jose import jwt

from itsdangerous import URLSafeSerializer, BadSignature
from flask import session, abort, redirect, url_for, request, Blueprint, Response, jsonify
from werkzeug.contrib.cache import SimpleCache, BaseCache

from flask_auth0.oidc import OpenIDConfig


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
        self.session_uid_key = uid_key

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
        self.session_uid_key = app.config.setdefault('AUTH0_SESSION_KEY', self.session_uid_key)

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

        app.register_blueprint(blueprint=blueprint, url_prefix=self.url_prefix)

    @staticmethod
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response

    def login_required(self, redirect_to_url_for=None):

        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                unauthorized = abort(401) if redirect_to_url_for is None else redirect(url_for(redirect_to_url_for))

                if self.is_authenticated:
                    return f(*args, **kwargs)
                return unauthorized

            return decorated_function
        return decorator

    @property
    def token_data(self):
        return self.cache.get(session.get(self.session_uid_key))

    @property
    def is_authenticated(self):
        pf = session.get(self.session_uid_key)
        if pf is not None:
            return self.cache.has(pf)
        return False

    @property
    def access_token(self):
        token_data = self.token_data
        return token_data.get('access_token') if self.token_data else None

    @property
    def refresh_token(self):
        token_data = self.token_data
        return token_data.get('refresh_token') if self.token_data else None

    @property
    def id_token(self):
        token_data = self.token_data
        return token_data.get('id_token') if self.token_data else None

    @property
    def token_type(self):
        token_data = self.token_data
        return token_data.get('token_type') if self.token_data else None

    @property
    def claims(self):
        token_data = self.token_data
        return token_data.get('claims') if self.token_data else None

    @property
    def sub(self):
        return self.claims.get('sub') if self.claims else None

    @property
    def authorization_header(self):
        return '%s %s' % (self.token_type, self.access_token)

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
        key_prefix = self.key_prefix
        self.cache.delete_many(
            '%s:token_type' % key_prefix,
            '%s:access_token' % key_prefix,
            '%s:refresh_token' % key_prefix,
            '%s:id_token' % key_prefix,
            '%s:id_token_claims' % key_prefix,
        )
        
        # Clear the session
        session.clear()
        
        # Redirect to auth0 logout
        params = {
            'returnTo': url_for('index', _external=True),
            'client_id': self.client_secret
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
            '%s?%s' % (self.openid_config.authorization_url, query_parameters)
        )

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
                self.app.logger.info(request.args.get('state'))
                return abort(400)

            token_data = requests.post(
                self.openid_config.token_url,
                data={
                    'code': code,
                    'grant_type': 'authorization_code',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'redirect_uri': url_for('flask-auth0.callback', _external=True)
                }).json()

            session[self.session_uid_key] = hexlify(generate_token(64)).decode('ascii')

            try:
                exp = token_data['expires_in']
            except KeyError:
                # Check for an error
                error = token_data.get('error')
                return abort(Response(error, status=400))
            else:
                # TODO: encrypt these values
                token_data['claims'] = self.verify_claims(token_data['id_token'])
                # Store the token data in the server-side cache under the id stored in the session
                self.cache.set(session[self.session_uid_key], token_data, timeout=exp)

                return redirect(state.get('return_to', '/'))

        return abort(401)

