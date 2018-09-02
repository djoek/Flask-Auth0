from functools import wraps, lru_cache
from urllib.parse import urlencode
from hashlib import blake2b

import uuid

import requests
from jose import jwt
from jose.exceptions import JWTError

from itsdangerous import URLSafeSerializer, BadSignature
from flask import session, abort, redirect, url_for, request, Blueprint, Response, current_app, g
from werkzeug.contrib.cache import SimpleCache, BaseCache

from flask_auth0.oidc import OpenIDConfig


__all__ = ("AuthorizationCodeFlow", )


class AuthorizationCodeFlow(object):

    def __init__(self, app=None,
                 *,
                 base_url=None,
                 client_id=None, client_secret=None,
                 cache=None,
                 scope='openid',
                 url_prefix='/oauth2', session_key='flask-auth0-cookie'):

        # :param app: Flask app
        # :param base_url: your identity provider's base url
        # :param client_id: CLIENT_ID
        # :param client_secret: CLIENT_SECRET
        # :param cache: a cache object that implements `werkzeug.contrib.cache.BaseCache` to store the tokens in
        # :param scope: oauth2 scopes
        # :param url_prefix: what should be the prefix of all the routes needed for oauth2. default = /oauth2
        # :param session_key: name of the key used in the session to store the uid

        self.app = app

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.url_prefix = url_prefix
        self.session_key = session_key

        # User actions
        self._after_login_handler = None
        self._after_logout_handler = None
        self._after_refresh_handler = None

        # Setup backend cache
        if cache is None:
            self.cache = SimpleCache()
        elif isinstance(cache, BaseCache):
            self.cache = cache
        else:
            raise ValueError('your backend cache must implement `werkzeug.contrib.cache.BaseCache`')

        # Utilities
        self.signer = None
        self.openid_config = None
        self._hash_key = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        # Config of the extension
        self.client_id = app.config.setdefault('AUTH0_CLIENT_ID', self.client_id)
        self.client_secret = app.config.setdefault('AUTH0_CLIENT_SECRET', self.client_secret)
        self.base_url = app.config.setdefault('AUTH0_BASE_URL', self.base_url)
        self.scope = app.config.setdefault('AUTH0_SCOPE', self.scope)

        if self.client_id is None or self.client_secret is None or self.base_url is None:
            raise ValueError('Missing config variables ')

        self.session_key = app.config.setdefault('AUTH0_SESSION_KEY', self.session_key)
        self.url_prefix = app.config.setdefault('AUTH0_URL_PREFIX', self.url_prefix)

        # Utils
        self.signer = URLSafeSerializer(app.secret_key)
        self.openid_config = OpenIDConfig(self.base_url)
        self._hash_key = app.secret_key.encode()[:64] if not isinstance(app.secret_key, bytes) else app.secret_key[:64]

        # Routes
        blueprint = Blueprint('flask-auth0', __name__)

        blueprint.add_url_rule('/login', 'login', self.login)
        blueprint.add_url_rule('/logout', 'logout', self.logout)
        blueprint.add_url_rule('/callback', 'callback', self.callback)

        blueprint.before_app_request(self.get_auth_data)

        app.register_blueprint(blueprint=blueprint, url_prefix=self.url_prefix)

    def get_auth_data(self):
        # At the beginning of each request, get the tokens from the cache
        # and store them in Flask.g, which exists for the duration of the request.
        # If the user isn't logged in yet, this value will be an empty dict

        # Create a uuid in the session if one doesn't yet exist
        session.setdefault(self.session_key, uuid.uuid4())
        g.flask_auth0_tokens = self.cache.get(self._make_key('token_data')) or {}

    def login_required(self, f):
        # A basic decorator to protect routes
        # Returns 401 if the user is not authenticated, otherwise the route
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if self.is_authenticated:
                return f(*args, **kwargs)
            return abort(401)
        return decorated_function

    # Three decorators to make it easy for actions to trigger after login, logout, refresh
    def after_login(self, f):
        self._after_login_handler = f
        return f

    def after_logout(self, f):
        self._after_logout_handler = f
        return f

    def after_refresh(self, f):
        self._after_refresh_handler = f
        return f

    # Bunch of useful properties
    @property
    def is_authenticated(self):
        # If there's an access token, we consider the user logged in
        return hasattr(g, 'flask_auth0_tokens') and 'access_token' in g.flask_auth0_tokens

    @property
    def is_refreshable(self):
        # Checks whether there is a refresh token
        return self.cache.has(self._make_key('refresh_token'))

    @property
    def access_token(self):
        return g.flask_auth0_tokens.get('access_token')

    @property
    def token_type(self):
        return g.flask_auth0_tokens.get('token_type')

    @property
    def authorization_header(self):
        # Returns the value that should go in the Authorization header
        # when you want to use the access_token
        # This is a convenience function
        return f'{self.token_type} {self.access_token}'

    @property
    def refresh_token(self):
        return self.cache.get(self._make_key('refresh_token')) or {}

    @property
    def claims(self):
        return self.cache.get(self._make_key('claims')) or {}

    @property
    def login_url(self):
        # Returns the full url for doing a login
        return url_for('flask-auth0.login', _external=True)

    @property
    def logout_url(self):
        # Returns the full url for doing a logout
        return url_for('flask-auth0.logout', _external=True)

    def get_verified_claims(self, id_token):

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
                    current_app.logger.debug('id_token is expired')
                    return abort(403)
                except jwt.JWTClaimsError:
                    current_app.logger.debug('incorrect claims. check the audience and issuer')
                    return abort(403)
                except Exception:
                    current_app.logger.debug('invalid header. cannot parse id_token')
                    return abort(403)
                else:
                    return payload

        current_app.logger.debug('invalid header. no matching keys found')
        return abort(403)

    # Retrieves the OpenID userinfo_endpoint
    def get_user_info(self):
        current_app.logger.debug('get_user_info() was called')

        try:
            result = requests.get(
                self.openid_config.userinfo_url,
                headers={
                    'Authorization': self.authorization_header,
                    'Content-Type': 'application/json'})
            result.raise_for_status()
        except requests.HTTPError:
            return {}
        else:
            return result.json()

    # Route definitions
    def logout(self, return_to='/'):
        """
        Handler for logging out a user.
        This clears the server-side session entry and redirects to the index endpoint
        :return: redirect()
        """
        current_app.logger.debug('logout() was called')

        self.cache.delete_many(
            self._make_key('token_data'),
            self._make_key('refresh_token'),
            self._make_key('claims'),
        )
        session.clear()

        if callable(self._after_logout_handler):
            self._after_logout_handler()
            current_app.logger.debug('after_logout_handler() was called')

        return redirect(return_to)

    def login(self, return_to=None, prompt='login'):
        """
        Handler for logging in a user.
        This provides a redirect to the authorization url
        :return: redirect()
        """

        current_app.logger.debug('login() was called')

        assert prompt in {'none', 'login', 'consent', 'select_account'}

        if return_to is None:
            return_to = current_app.config.get('APPLICATION_ROOT', '/')

        query_parameters = {
            'response_type': 'code',
            'scope': self.scope,
            'state': self.signer.dumps({'return_to': return_to}),
            'client_id': self.client_id,
            'prompt': prompt,
            # Not strictly necessary to send this along, but when omitted,
            # the user is redirected to the uri configured in the oauth2 backend
            #
            # 'redirect_uri': url_for('flask-auth0.callback', _external=True),
        }

        return redirect(f'{self.openid_config.authorization_url}?{urlencode(query_parameters)}')

    def callback(self):
        """
        Handler for the OAuth2 callback
        This gets the code and turns it into tokens
        :return: redirect()
        """
        current_app.logger.debug('callback() was called')

        # try to login using the code in the url arg
        if 'code' in request.args:

            try:  # to get the state
                state = self.signer.loads(request.args.get('state'))
            except BadSignature:  # State has been tampered with
                return abort(403)

            # Get the tokens using the code
            token_result = requests.post(
                self.openid_config.token_url,
                data={
                    'code': request.args.get('code'),
                    'grant_type': 'authorization_code',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'redirect_uri': url_for('flask-auth0.callback', _external=True)
                })
            token_result.raise_for_status()
            token_data = token_result.json()

            # Handle errors
            if 'error' in token_data:
                return abort(Response(token_data.get('error'), status=401))
            else:
                self._update_tokens(**token_data)

            # Execute user actions
            if callable(self._after_login_handler):
                self._after_login_handler()
                current_app.logger.debug('after_login_handler() was called')

            # Get return url from the state
            return_to = state.get('return_to')
            if return_to:
                return redirect(return_to)

            # Fall back on a default
            return Response('Login Successful', status=200)

        # No code in url, return an error
        return abort(403)

    # Convenience functions
    def refresh(self):
        """
        Handler for the OAuth2 token refresh
        This exchanges the refresh_token for a new access_token
        :return: None
        """
        current_app.logger.debug('refresh() was called')

        token_result = requests.post(
            self.openid_config.token_url,
            data={
                'grant_type': 'refresh_token',
                'scope': self.scope,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': self.refresh_token,
            },
        )
        token_result.raise_for_status()
        token_data = token_result.json()

        current_app.logger.debug(f'refresh got {token_data}')

        self._update_tokens(**token_data)

        if callable(self._after_refresh_handler):
            self._after_refresh_handler()
            current_app.logger.debug('after_refresh_handler() was called')

    # Logic for updating the cache with new token info
    def _update_tokens(self, *,
                       access_token, token_type='Bearer',
                       refresh_token=None,
                       id_token=None,
                       expires_in=3600, **kwargs):

        # not saving the id_token since it's short-lived
        # and serves no purpose after we validated the claims
        g.flask_auth0_tokens = {
            'token_type': token_type,
            'access_token': access_token,
        }

        # Update the cache for the next request
        self.cache.set(
            self._make_key('token_data'),
            g.flask_auth0_tokens,
            timeout=expires_in)

        # Handle the id_token if present
        if id_token is not None:
            # The id_token is a JWT that requires verification and decoding
            claims = self.get_verified_claims(id_token)

            if claims:
                self.cache.set(
                    self._make_key('claims'),
                    claims,
                    # id_tokens express their validity in absolute timestamps
                    # our cache layers wants relative seconds, so math
                    timeout=claims.get('exp') - claims.get('iat'))

        # Handle the refresh_token if present
        if refresh_token is not None:
            self.cache.set(
                self._make_key('refresh_token'),
                refresh_token,
                # refresh tokens in principle don't expire,
                # being a bit more conservative here
                timeout=7 * 24 * 60 * 60)

    # To further obfuscate the relation between the cache key and the session id,
    # the token itself is cryptographically hashed, and that hash is used as the key in the backend cache
    # Is this strictly necessary to make it work? No, but it seemed like a cool thing to do :)
    def _make_key(self, value: str):
        uid = session.get(self.session_key)
        return self._obfuscate_value(value=value.encode(), uid=uid.bytes)

    # Since the function below is idempotent, we can use a cache
    # instead of recalculating the same value over and over again
    @lru_cache(maxsize=256)
    def _obfuscate_value(self, value: bytes, uid: bytes):
        hs = blake2b(key=self._hash_key, person=uid)
        hs.update(value)
        return hs.hexdigest()
