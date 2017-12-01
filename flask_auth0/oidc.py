from requests import get
from urllib.parse import urljoin


class OpenIDConfig:

    def __init__(self, base_url):
        openid_result = get(
            urljoin(base_url, '.well-known/openid-configuration')
        )
        openid_result.raise_for_status()

        self.openid_config = openid_result.json()

    @property
    def token_url(self):
        return self.openid_config['token_endpoint']

    @property
    def userinfo_url(self):
        return self.openid_config['userinfo_endpoint']

    @property
    def authorization_url(self):
        return self.openid_config['authorization_endpoint']

    @property
    def jwks_uri(self):
        return self.openid_config['jwks_uri']

    @property
    def issuer(self):
        return self.openid_config['issuer']
