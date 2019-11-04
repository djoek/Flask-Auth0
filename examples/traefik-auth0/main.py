import os

from flask import Flask, request, make_response
from flask_auth0 import AuthorizationCodeFlow

from werkzeug.middleware.proxy_fix import ProxyFix

from cachelib import FileSystemCache


app = Flask(__name__, template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

app.secret_key = os.getenv('SECRET_KEY')

# You can add the config to the app or to the ext
app.config['AUTH0_CLIENT_ID'] = os.getenv('AUTH0_CLIENT_ID')
app.config['AUTH0_CLIENT_SECRET'] = os.getenv('AUTH0_CLIENT_SECRET')

# Initialize the extension
auth = AuthorizationCodeFlow(
    app=app,  # or use auth.init_app() later
    scope='profile',
    base_url=os.getenv('AUTH0_BASE_URL'),  # The base url of your SSO
    # All your instances need to be able to access this path,
    # or use another backend like Redis
    cache=FileSystemCache('/tmp/flask_auth0_cache')
)


@app.route('/oauth2/knock')
@auth.protected(enforce=False)
def web_auth():
    if auth.is_authenticated:

        response = make_response('OK', 200)
        response.headers['X-Auth-User'] = auth.get_verified_claims(auth.id_token).get('name')

        return response

    h = request.headers
    return auth.login(return_to=f'{h["X-Forwarded-Proto"]}://{h["X-Forwarded-Host"]}{h["X-Forwarded-Uri"]}')
