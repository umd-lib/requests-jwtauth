import json
from time import time
from typing import Optional

from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from requests.auth import AuthBase


class HTTPBearerAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = f'Bearer {self.token}'
        return r


class JWTSecretAuth(AuthBase):
    def __init__(
            self,
            secret: str,
            claims: Optional[dict] = None,
            ttl: Optional[int] = 3600,
            expiration_buffer: Optional[int] = 60,
            signing_algorithm: Optional[str] = 'HS256',
    ):
        self.secret = secret
        self.claims = claims or {}
        self.ttl = ttl
        self.expiration_buffer = expiration_buffer
        self.signing_algorithm = signing_algorithm
        self.token: Optional[JWT] = None
        self.key = JWK(kty='oct', k=self.secret)

    def __call__(self, r):
        if self.should_renew_token:
            expiration_time = time() + self.ttl
            # generate a new token
            self.token = JWT(
                header={
                    'alg': self.signing_algorithm,
                },
                claims={
                    **self.claims,
                    'exp': expiration_time,
                }
            )
            self.token.make_signed_token(self.key)

        r.headers['Authorization'] = f'Bearer {self.token.serialize()}'
        return r

    @property
    def token_expiration(self):
        return json.loads(self.token.claims).get('exp')

    @property
    def should_renew_token(self):
        return self.token is None or (self.token_expiration - self.expiration_buffer) < time()

    @property
    def token_is_expired(self):
        return self.token is None or self.token_expiration < time()
