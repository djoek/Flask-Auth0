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
from flask import session, abort, redirect, url_for, request, Blueprint, Response
from werkzeug.contrib.cache import SimpleCache, BaseCache

from flask_auth0.oidc import OpenIDConfig


class AuthorizationCodeFlow(object):

    def __init__(self, app=None,
                 *,
                 base_url=None,
                 client_id=None, client_secret=None,
                 cache=None,
                 scope='openid',
                 url_prefix='/oauth2', session_key='auth0'):

        self.app = app

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.url_prefix = url_prefix
        self.session_key = session_key

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
        self.session_key = app.config.setdefault('AUTH0_SESSION_KEY', self.session_key)

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

        app.register_blueprint(blueprint=blueprint, url_prefix=self.url_prefix)

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
    def key_prefix(self):
        return session.get(self.session_key)

    @property
    def is_authenticated(self):
        return self.cache.has('%s:access_token' % self.key_prefix)

    @property
    def access_token(self):
        return self.cache.get('%s:access_token' % self.key_prefix)

    @property
    def refresh_token(self):
        return self.cache.get('%s:refresh_token' % self.key_prefix)

    @property
    def id_token(self):
        return self.cache.get('%s:id_token' % self.key_prefix)

    @property
    def token_type(self):
        return self.cache.get('%s:token_type' % self.key_prefix)

    @property
    def sub(self):
        claims = self.cache.get('%s:id_token_claims' % self.key_prefix)
        return claims.get('sub')

    @property
    def authorization_header(self):
        return '%s %s' % (self.token_type, self.access_token)

    def get_verified_claims(self):

        # We can get the info in the id_token, but it needs to be verified
        u_header, u_claims = jwt.get_unverified_header(self.id_token), jwt.get_unverified_claims(self.id_token)
        # Get the key which was used to sign this id_token
        kid, alg = u_header['kid'], u_header['alg']

        # Obtain JWT and the keys to validate the signature
        jwks_response = requests.get(self.openid_config.jwks_uri).json()
        for key in jwks_response['keys']:
            if key['kid'] == kid:
                payload = jwt.decode(
                    token=self.id_token, key=key,
                    audience=self.client_id,
                    issuer=self.openid_config.issuer)
                return payload

        return {}

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

            key_prefix = hexlify(generate_token(64)).decode('ascii')
            session[self.session_key] = key_prefix

            try:
                exp = token_data['expires_in']
            except KeyError:
                # Check for an error
                error = token_data.get('error')
                return abort(Response(error, status=400))
            else:
                # TODO: encrypt these values
                self.cache.set('%s:access_token' % key_prefix, token_data.get('access_token'), timeout=exp)
                self.cache.set('%s:refresh_token' % key_prefix, token_data.get('refresh_token'), timeout=exp)
                self.cache.set('%s:id_token' % key_prefix, token_data.get('id_token'), timeout=exp)
                self.cache.set('%s:token_type' % key_prefix, token_data.get('token_type'), timeout=exp)

                id_token_claims = self.get_verified_claims()
                self.cache.set('%s:id_token_claims' % key_prefix, id_token_claims,
                               timeout=id_token_claims.get('exp', exp))

                return redirect(state.get('return_to', '/'))

        return abort(401)
