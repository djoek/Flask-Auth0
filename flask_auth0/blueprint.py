from urllib.parse import urlencode

import requests
from flask import Blueprint, session, url_for, redirect, request, abort, current_app
from itsdangerous import BadSignature
from jose import jwt

from flask_auth0.user import User

auth0 = Blueprint('auth0', __name__, template_folder='./templates')


@auth0.route('/logout', methods=['GET'])
def logout():
    """
    Handler for logging out a user.
    This clears the server-side session entry and redirects to the logout endpoint
    :return: redirect()
    """
    del session[current_app.config['AUTH0_SESSION_KEY']]
    params = {
        'returnTo': url_for('index', _external=True),
        'client_id': current_app.config['AUTH0_CLIENT_ID']
    }
    return redirect(current_app.auth0_oidc.issuer + 'v2/logout?' + urlencode(params))


@auth0.route('/login', methods=['GET'])
def login():
    """
    Handler for logging in a user.
    This provides a redirect to the authorization url
    :return: redirect()
    """

    state = current_app.auth0_signer.dumps({'return_to': request.referrer or '/'})

    query_parameters = urlencode({
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state,
        'client_id': current_app.config['AUTH0_CLIENT_ID'],
        'redirect_uri': url_for('auth0.oauth2_callback', _external=True)
    })
    return redirect(
        f"{current_app.auth0_oidc.authorization_url}?{query_parameters}"
    )


@auth0.route('/callback', methods=['GET'])
def oauth2_callback():
    """
    Handler for the OAuth2 callback
    This gets the code and turns it into tokens
    :return: redirect()
    """
    # try to login using the code in the url arg
    code = request.args.get('code')
    if code:

        try:  # to get the state
            state = current_app.auth0_signer.loads(request.args.get('state'))

        except BadSignature:
            # State has been tampered with
            current_app.logger.info(request.args.get('state'))
            return abort(400)

        token_data = requests.post(
            current_app.auth0_oidc.token_url,
            data={
                'code': code,
                'grant_type': 'authorization_code',
                'client_id': current_app.config['AUTH0_CLIENT_ID'],
                'client_secret': current_app.config['AUTH0_CLIENT_SECRET'],
                "redirect_uri": url_for('auth0.oauth2_callback', _external=True)
            },
        ).json()

        # Obtain JWT and the keys to validate the signature
        keys = requests.get(current_app.auth0_oidc.jwks_uri).json()
        payload = jwt.decode(token=token_data['id_token'],
                             key=keys,
                             algorithms=['RS256'],
                             audience=current_app.config['AUTH0_CLIENT_ID'],
                             issuer=current_app.auth0_oidc.issuer)

        session[current_app.config['AUTH0_SESSION_KEY']] = User(**payload)
        return redirect(state.get('return_to', '/'))

    return abort(401)
