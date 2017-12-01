import os

from flask import Flask, jsonify, render_template, request, session
from flask_auth0 import AuthorizationCodeFlow

from werkzeug.contrib.cache import FileSystemCache

app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY')

# This is a demo so debug mode is enabled for maximal output
# DON'T DO THIS IN PRODUCTION
app.env = 'development'
app.debug = True

# You can add the config to the app or to the ext
app.config['AUTH0_CLIENT_ID'] = os.getenv('AUTH0_CLIENT_ID')
app.config['AUTH0_CLIENT_SECRET'] = os.getenv('AUTH0_CLIENT_SECRET')

# Initialize the extension
auth = AuthorizationCodeFlow(
    app=app,  # or use auth.init_app() later
    scope='openid '       # Gives you access to the user's info. You probably want this
          'profile '      # Gives you user's full name, title, company and access level
          'email phone',  # extra fields in the user_info
    base_url=os.getenv('AUTH0_BASE_URL'),  # The base url of your SSO
    # All your instances need to be able to access this path,
    # or use another backend like Redis
    cache=FileSystemCache('/tmp/flask_auth0_cache')
)


# Get the OIDC user info and store it somewhere in the app
# Most likely you want to keep a user object somewhere and update it with this
# For demo purposes, we store it in the user's session.
# This stores the info in a cookie on the browser.
@auth.after_login
def update_user_info():
    user = auth.get_user_info()


# When Flask-PingFederate fails to authenticate the user, it returns a 401 Response
# This function handles that and allows you to show a custom page
@app.errorhandler(401)
def authorization_failure(e):
    return render_template('unauthorized.html', e=e)


# Base url for the app
@app.route('/')
def index():
    return render_template('index.html')


# Example Protected resource, with custom logic
@app.route('/secret')
@auth.protected()
def web_secret():
    if not auth.is_authenticated:
        # redirect to login and return to this page if successful
        return auth.login(return_to=request.url)
    return render_template('secret.html')


# Example Protected resource
@app.route('/user_info')
@auth.protected(enforce=True)
def user_info():
    return jsonify({
        'user_info': auth.get_user_info(),
        'claims': auth.get_verified_claims()
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")

