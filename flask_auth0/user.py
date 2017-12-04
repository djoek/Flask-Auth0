from datetime import datetime


class User:

    def __init__(self, *args, **kwargs):
        self.payload = kwargs

    @property
    def is_authenticated(self):
        return self.payload.get('iat', 0) < datetime.utcnow().timestamp() < self.payload.get('exp', 0)

    @property
    def is_admin(self):
        return self.payload.get('role', None) == 'admin'

    @property
    def nickname(self):
        return self.payload.get('nickname')

    @property
    def username(self):
        return self.payload.get('sub')

    @property
    def role(self):
        return self.payload.get('role')

    def __str__(self):
        return self.nickname

    def __repr__(self):
        return f"<User {self.nickname} {'Authenticated' if self.is_authenticated else 'Expired'}>"
