from datetime import datetime


class User:

    def __init__(self, *args, **kwargs):
        self.payload = kwargs

    @property
    def is_authenticated(self):
        return self.payload.get('iat', 0) < datetime.utcnow().timestamp() < self.payload.get('exp', 0)

    @property
    def is_admin(self):
        return self.payload.get('is_admin', False)

    @property
    def nickname(self):
        return self.payload.get('nickname')

    @property
    def role(self):
        return self.payload.get('role')

    def __str__(self):
        return self.payload['nickname']

    def __repr__(self):
        return f"<User {self.payload.get('sub')}>"
