from dataclasses import dataclass, InitVar
from datetime import datetime


@dataclass
class RedisTokenCache:

    access_token: str
    expires_in: InitVar[int]
    token_type: str = 'Bearer'
    refresh_token: str = ''
    id_token: str = ''

    def __post_init__(self, expires_in):
        self.expires = int(datetime.utcnow().timestamp()) + expires_in

    def store(self, redis_instance, prefix=""):
        expires_in = self.expires - int(datetime.utcnow().timestamp())
        with redis_instance.pipeline() as rp:
            rp.set(f"{prefix}access_token", self.access_token, ex=expires_in)
            rp.set(f"{prefix}token_type", self.token_type, ex=expires_in)
            rp.set(f"{prefix}refresh_token", self.refresh_token, ex=expires_in)
            rp.set(f"{prefix}id_token", self.id_token, ex=expires_in)

    @classmethod
    def retrieve(cls, redis_instance, prefix=""):
        access_token, token_type, refresh_token, id_token = redis_instance.mget(
            f"{prefix}access_token", f"{prefix}token_type", f"{prefix}refresh_token", f"{prefix}id_token")

        return cls(
            access_token=access_token,
            expires_in=redis_instance.ttl(f"{prefix}access_token"),
            token_type=token_type,
            refresh_token=refresh_token,
            id_token=id_token,
        )

    def authorization_header(self) -> str:
        return f"{self.token_type} {self.access_token}"
