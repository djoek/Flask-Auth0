# Flask-Auth0

Flask-Auth0 is a Flask extension that aims to make it easy to integrate your application with authentication as offered by Auth0.  
Right now, it offers only Authorization Code Flow.  

In time, it may support more features that Auth0 offers (like Administration API access via Client Credentials, API protection, ...)


# Quick start

Please see the Examples folder for more details.

This example assumed that you went through the process of creating an application on Auth0, 
and have your BASE_URL, CLIENT_ID and CLIENT_SECRET available as environment variables prefixed with AUTH0_
You can also set the allowed callback URL and logout URL.  

Flask-Auth0 provides routes named /oauth2/login, /oauth2/logout, /oauth2/callback for this purpose 


```python
import os

from flask import Flask, render_template, request
from flask_auth0 import AuthorizationCodeFlow

from werkzeug.contrib.cache import FileSystemCache

app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY')

# You can add the config to the app or to the ext
app.config['AUTH0_CLIENT_ID'] = os.getenv('AUTH0_CLIENT_ID')
app.config['AUTH0_CLIENT_SECRET'] = os.getenv('AUTH0_CLIENT_SECRET')

# Initialize the extension
auth = AuthorizationCodeFlow(
    app=app,  # or use auth.init_app() later
    scope='openid profile',
    base_url=os.getenv('AUTH0_BASE_URL'),  # The base url of your SSO
    # All your instances need to be able to access this path,
    # You can use another backend like Redis as long as it's a werkzeug Cache object
    cache=FileSystemCache('/tmp/flask_auth0_cache')
)


# You can use the .after_login, .after_logout and .after refresh decorators 
# To update your backend user database with the info
@auth.after_login
def update_user_info():
    user = auth.get_user_info()


# Base url for the app
@app.route('/')
def index():
    return render_template('index.html')
    
# Example Protected resource
@app.route('/secret1')
@auth.protected(enforce=True)  # enforce = return 401 if not authenticated
def user_info():
    return "Hello, Secret 1!"

# Example Protected resource, with custom logic
@app.route('/secret2')
@auth.protected()
def web_secret():
    if not auth.is_authenticated:
        # redirect to login and return to this page if successful
        return auth.login(return_to=request.url)
    return "Hello, Secret 2!"

```