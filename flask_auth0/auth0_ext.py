from functools import wraps, lru_cache
from urllib.parse import urlencode
from hashlib import blake2b, scrypt

import uuid

import requests
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

from itsdangerous import URLSafeSerializer, BadSignature
from flask import session, redirect, url_for, request, Blueprint, Response, g

from werkzeug.exceptions import \
    BadRequest, Unauthorized, Forbidden, InternalServerError, ServiceUnavailable
from cachelib import SimpleCache, BaseCache

from flask_auth0.oidc import OpenIDConfig
from flask_auth0.__version__ import __version__


__all__ = ('AuthorizationCodeFlow', )


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
        self.user_agent = f"{__name__}/{__version__} python-requests/{requests.__version__}"

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

        self._logger = None

        # Setup backend cache
        if cache is None:
            self.cache = SimpleCache()
        elif isinstance(cache, BaseCache):
            self.cache = cache
        else:
            raise ValueError(
                f'your backend cache must implement `cachelib.BaseCache`. {cache} is {type(cache)}')

        # Utilities
        self.signer = None
        self.hasher = None

        self.openid_config = None

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

        # Setup some crypto stuff.
        # I am not a cryptographer and might do this wrong. For prod use, tweak appropriately.
        # If you don't know why or what into you should change these values,
        # google for "Key Derivation Function" or ask someone with a Security background
        key_material = scrypt(
            password=app.secret_key.encode(),
            salt=b'flask-auth0',
            dklen=32, n=256, r=8, p=1)

        # Utils
        self.signer = URLSafeSerializer(key_material[:16])
        self.hasher = lru_cache(maxsize=256)(  # Because this is non-trivial, we cache already computes values
            lambda value, uid: blake2b(value, key=key_material[16:], person=uid, digest_size=32).digest())

        self._logger = app.logger
        self.openid_config = OpenIDConfig(self.base_url)

        # Routes
        blueprint = Blueprint('flask-auth0', __name__)

        blueprint.add_url_rule('/login', 'login', self.login)
        blueprint.add_url_rule('/logout', 'logout', self.logout)
        blueprint.add_url_rule('/callback', 'callback', self.callback)

        app.register_blueprint(blueprint=blueprint, url_prefix=self.url_prefix)

    def protected(self, enforce=False):
        """
        This decorator indicates that the auth info needs to be available in the decorated route
        :param enforce: returns 401 if the auth info is not available
        :return:
        """
        def actual_decorator(func):

            @wraps(func)
            def decorated_function(*args, **kwargs):
                if enforce:
                    if self.is_authenticated:
                        return func(*args, **kwargs)
                    raise Unauthorized()
                return func(*args, **kwargs)

            return decorated_function

        return actual_decorator

    # Three decorators to make it easy for actions to trigger after login, logout, refresh
    def after_login(self, func):
        self._after_login_handler = func
        return func

    def after_logout(self, func):
        self._after_logout_handler = func
        return func

    def after_refresh(self, func):
        self._after_refresh_handler = func
        return func

    # Bunch of useful properties
    @property
    def is_authenticated(self):
        # If there's an access token, we consider the user logged in
        return self.access_token is not None

    @property
    def is_refreshable(self):
        # Checks whether there is a refresh token
        return session.get(self.session_key) is not None and self.cache.has(self._make_key('refresh_token'))

    @property
    def access_token(self):
        return self.cache.get(self._make_key('access_token'))

    @property
    def token_type(self):
        return self.cache.get(self._make_key('token_type'))

    @property
    def authorization_header(self):
        # Returns the value that should go in the Authorization header
        # when you want to use the access_token
        # This is a convenience function
        return f'{self.token_type} {self.access_token}'

    @property
    def id_token(self):
        return self.cache.get(self._make_key('id_token'))

    @property
    def refresh_token(self):
        return self.cache.get(self._make_key('refresh_token'))

    @lru_cache(maxsize=1024)
    def get_verified_claims(self, id_token):
        # Converts the jwt id_token into verified claims
        try:
            # We can get the info in the id_token, but it needs to be verified
            u_header, u_claims = jwt.get_unverified_header(id_token), jwt.get_unverified_claims(id_token)

            # Get the key which was used to sign this id_token
            kid, alg = u_header['kid'], u_header['alg']

        except JWTError:
            self._logger.warn('Tried to verify claims of a broken id_token')
            return {}

        else:
            # Obtain JWT and the keys to validate the signature
            try:
                jwks_response = requests.get(
                    self.openid_config.jwks_uri,
                    headers={
                        'User-Agent': self.user_agent,
                    },
                )
            except requests.HTTPError:
                return {}
            else:
                jwks_data = jwks_response.json()
                try:
                    for key in jwks_data['keys']:
                        if key['kid'] == kid:
                            payload = jwt.decode(
                                token=id_token, key=key,
                                audience=self.client_id,
                                issuer=self.openid_config.issuer)
                            return payload
                except ExpiredSignatureError:
                    self._logger.warn('Tried to verify claims of an expired id_token')

        return {}

    # Retrieves the OpenID userinfo_endpoint
    def get_user_info(self):
        self._logger.debug('get_user_info() was called')

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

    def logout_url(self, return_to=None):

        if return_to is None:
            return_to = request.args.get('return_to') or request.referrer or '/'

        # Redirect to auth0 logout
        params = {
            'returnTo': return_to or url_for('index', _external=True),
            'client_id': self.client_id}

        return f'{self.openid_config.issuer}v2/logout?{urlencode(params)}'

    # Route definitions
    def logout(self, return_to=None):
        """
        Handler for logging out a user.
        This clears the server-side session entry and redirects to the index endpoint
        :return: redirect()
        """
        self._logger.debug('logout() was called')

        self.cache.delete_many(
            self._make_key('token_data'),
            self._make_key('refresh_token'),
        )
        session.clear()

        if callable(self._after_logout_handler):
            self._after_logout_handler()
            self._logger.debug('after_logout_handler() was called')

        return redirect(self.logout_url(return_to=return_to))

    def login_url(self, return_to=None, prompt='login', response_type='code', redirect_uri=None):

        # Returns the full url for doing a login
        if prompt not in {'none', 'login', 'consent', 'select_account'}:
            raise ValueError('Invalid prompt')
        if response_type not in {'code', 'token'}:
            raise ValueError('Invalid response_type')

        if return_to is None:
            return_to = request.args.get('return_to') or request.referrer or '/'

        if redirect_uri is None:
            redirect_uri = url_for('flask-auth0.callback', _external=True)

        query_parameters = {
            'response_type': response_type,
            'scope': self.scope,
            'state': self.signer.dumps({'return_to': return_to}),
            'client_id': self.client_id,
            'prompt': prompt,
            # Not strictly necessary to include redirect_uri, but avoids potential issues
            'redirect_uri': redirect_uri,
        }

        return f'{self.openid_config.authorization_url}?{urlencode(query_parameters)}'

    def login(self, return_to=None, prompt='login', response_type='code', redirect_uri=None):
        """
        Handler for logging in a user.
        This provides a redirect to the authorization url
        :return: redirect()
        """
        self._logger.debug('login() was called')
        return redirect(
            self.login_url(
                return_to=return_to,
                prompt=prompt,
                response_type=response_type,
                redirect_uri=redirect_uri
            )
        )

    def callback(self):
        """
        Handler for the OAuth2 callback
        This gets the code and turns it into tokens
        :return: redirect()
        """
        self._logger.debug('callback() was called')

        try:  # to get the state
            state = self.signer.loads(request.args.get('state'))
        except BadSignature:  # State has been tampered with
            return BadRequest(description="State could not be validated")
        except TypeError:  # state is None, not in the url
            state = {}

        # Handle callback errors
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        error_uri = request.args.get('error_uri')

        if error is not None:
            return self.callback_error_handler(
                error=error,
                error_description=error_description,
                error_uri=error_uri, state=state
            )

        code = request.args.get('code')
        if code is not None:  # try to login using the code in the url arg

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

            try:
                token_data = token_result.json()

                # Handle errors in access token request
                error = token_data.get('error')
                error_description = token_data.get('error_description')
                error_uri = token_data.get('error_uri')
                if error is not None:
                    return self.access_token_request_error_handler(
                        error=error,
                        error_description=error_description,
                        error_uri=error_uri)

                # Raise for other HTTP trouble
                token_result.raise_for_status()

            except requests.HTTPError as e:
                self._logger.error(f'Could not exchange code for access_token: {e}')
                raise InternalServerError(
                    description=f"Could not obtain access_token with code")

            else:
                session[self.session_key] = uuid.uuid4()
                self._update_tokens(**token_data)

            # Execute user actions
            if callable(self._after_login_handler):
                self._logger.debug('after_login_handler() was called')
                self._after_login_handler()

            # Get return url from the state
            return_to = state.get('return_to')
            if return_to:
                self._logger.debug(f'Returning to {return_to}')
                return redirect(return_to)

            # Fall back on a default
            return Response('Login Successful', status=200)

        else:  # No code in url, return an error
            return Unauthorized(description="Unauthorized")

    def verify_email(self):
        email = request.args.get('email')
        message = request.args.get('message')
        success = request.args.get('success')

    # Convenience functions
    def refresh(self):
        """
        Handler for the OAuth2 token refresh
        This exchanges the refresh_token for a new access_token
        :return: None
        """
        self._logger.debug('refresh() was called')

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
        # TODO: better error handling (see callback)
        token_result.raise_for_status()
        token_data = token_result.json()

        self._update_tokens(**token_data)

        if callable(self._after_refresh_handler):
            self._after_refresh_handler()
            self._logger.debug('after_refresh_handler() was called')

    # Logic for updating the cache with new token info
    def _update_tokens(self, *,
                       access_token, token_type='Bearer',
                       refresh_token=None,
                       id_token=None,
                       expires_in=3600, **kwargs):

        self._logger.debug('update_tokens() was called')

        if kwargs:
            self._logger.debug(f'got extra token data: {kwargs.keys()}')

        if id_token is not None:
            self.cache.set(
                self._make_key('id_token'),
                id_token,
                timeout=expires_in)

        # Update the cache for the next request
        self.cache.set(
            self._make_key('access_token'),
            access_token,
            timeout=expires_in)

        self.cache.set(
            self._make_key('token_type'),
            token_type,
            timeout=expires_in)

        # Handle the refresh_token if present
        # it doesn't have a timeout since the refresh token shouldn't expire
        if refresh_token is not None:
            self.cache.set(
                self._make_key('refresh_token'),
                refresh_token, )

    # To further obfuscate the relation between the cache key and the session id,
    # the token itself is cryptographically hashed, and that hash is used as the key in the backend cache
    # Is this strictly necessary to make it work? No, but it seemed like a cool thing to do :)
    def _make_key(self, value: str):
        uid = session.setdefault(self.session_key, uuid.uuid4())
        return self.hasher(value=value.encode(), uid=uid.bytes)

    @property
    def session_id(self):
        return session.get(self.session_key)

    def callback_error_handler(
            self, error, error_description=None, error_uri=None, state=None):

        self._logger.error(f'{error}: {error_description} {error_uri} {state}')

        error_mapping = {
            'invalid_request': BadRequest,  # 400
            'unauthorized': Unauthorized,  # 401
            'unauthorized_client': Unauthorized,  # 401
            'access_denied': Forbidden,  # 403
            'unsupported_response_type': Forbidden,  # 403
            'invalid_scope': Forbidden,  # 403
            'server_error': InternalServerError,  # 500
            'temporarily_unavailable': ServiceUnavailable,  # 503
        }

        HTTPError = error_mapping.get(error, BadRequest)  # 400
        raise HTTPError(description=error_description)

    def access_token_request_error_handler(
            self, error, error_description=None, error_uri=None):

        self._logger.error(f'{error}: {error_description} {error_uri}')

        if error == 'invalid_scope':
            pass

        if error == 'unsupported_grant_type':
            pass

        if error == 'unauthorized_client':
            pass

        if error == 'invalid_grant':
            pass

        if error == 'invalid_client':
            pass

        if error == 'invalid_request':
            pass

        raise InternalServerError(description="error trying to obtain access_token")
