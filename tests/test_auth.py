import datetime
import json
import re
import time
from datetime import timedelta

import pytest
from freezegun import freeze_time
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from requests import Session, Request

from requests_jwtauth import HTTPBearerAuth, JWTSecretAuth


@pytest.fixture
def get_request():
    return Request(method='get', url='http://localhost:9999/')


@pytest.fixture
def secret():
    return '833eba93802fdfce0e3d852b0bcb624f974551864e31e5d57920471f4a6a77e7'


def test_http_bearer_auth(get_request):
    auth = HTTPBearerAuth(token='abcd-1234')
    session = Session()
    session.auth = auth
    r = session.prepare_request(get_request)

    assert 'Authorization' in r.headers
    assert r.headers['Authorization'] == 'Bearer abcd-1234'


def test_jwt_secret_auth(get_request, secret):
    auth = JWTSecretAuth(secret=secret)
    session = Session()
    session.auth = auth
    r = session.prepare_request(get_request)

    assert 'Authorization' in r.headers
    assert r.headers['Authorization'] == f'Bearer {auth.token.serialize()}'


def test_auth_jwt_secret_expiration(get_request, secret):
    initial_datetime = datetime.datetime(year=2021, month=2, day=19,
                                         hour=13, minute=0, second=0)
    with freeze_time(initial_datetime) as frozen_datetime:
        auth = JWTSecretAuth(secret=secret)
        session = Session()
        session.auth = auth
        session.prepare_request(get_request)
        assert not auth.token_is_expired

        # JWTSecretAuth tokens valid up to one hour
        frozen_datetime.tick(delta=datetime.timedelta(hours=1))
        assert not auth.token_is_expired

        # JWTSecretAuth tokens expire after one hour
        frozen_datetime.tick(delta=datetime.timedelta(seconds=1))
        assert auth.token_is_expired


def test_auth_jwt_secret_tokens_can_be_refreshed(get_request, secret):
    initial_datetime = datetime.datetime(year=2021, month=2, day=19,
                                         hour=13, minute=0, second=0)
    with freeze_time(initial_datetime) as frozen_datetime:
        auth = JWTSecretAuth(secret=secret)
        session = Session()
        session.auth = auth
        session.prepare_request(get_request)

        # JwtSecretAuth tokens expire after one hour
        frozen_datetime.tick(delta=datetime.timedelta(hours=1, seconds=1))
        assert auth.token_is_expired

        # Refresh token
        r = session.prepare_request(get_request)
        assert not auth.token_is_expired

        # Verify that session is using refreshed token
        session_jwt_token = re.search('Bearer (.*)', r.headers['Authorization']).group(1)
        expiration_datetime = expiration_datetime_from_jwt_token(session_jwt_token, secret)

        expected_expiration_time = datetime.datetime.fromtimestamp(time.time()) + timedelta(hours=1)

        assert expected_expiration_time == expiration_datetime


def expiration_datetime_from_jwt_token(jwt_token: str, jwt_secret: str) -> datetime:
    key = JWK(kty='oct', k=jwt_secret)
    jwt = JWT(jwt=jwt_token, key=key)

    jwt_claims_json = jwt.claims
    claims = json.loads(jwt_claims_json)
    expiration_datetime = datetime.datetime.fromtimestamp(claims['exp'])
    return expiration_datetime
