# requests-jwtauth

Authenticator plugins for [Requests] that support JWT bearer tokens.

## Description

This package contains two classes, `HTTPBearerAuth` and `JWTSecretAuth`,
that implement the [AuthBase] interface from the [Requests] package. The
`HTTPBearerAuth` class takes a single bearer token value at initialization,
and adds that to an `Authorization: Bearer` header. The
`JWTSecretAuth` class takes a shared secret, and uses that to generate and
sign short-lived [JWT] tokens to be added to an `Authorization: Bearer`
request header. By default, these tokens are valid for 1 hour (3600
seconds), and may contain arbitrary [JWT claims] in their payload.

## Dependencies

* Python 3.8+
* [Requests]
* [JWCrypto]

## Installation

With **pip**:

```bash
pip install git+https://github.com/umd-lib/requests-jwtauth.git
```

In your **pyproject.toml** file:

```toml
[project]
# ...
dependencies = [
    "requests-jwtauth@git+https://github.com/umd-lib/requests-jwtauth.git"
    # ...
]
```

## Usage

### HTTPBearerAuth

```python
import requests
from requests_jwtauth import HTTPBearerAuth

# send a request with a pre-obtained bearer token
my_token = '...'
r = requests.get('http://example.com', auth=HTTPBearerAuth(my_token))
```

### JWTSecretAuth

```python
import requests
from requests_jwtauth import JWTSecretAuth

# use a shared secret to generate (and automatically regenerate)
# short-lived JWT bearer tokens

secret_auth = JWTSecretAuth(
    # shared secret with the service that requires authentication
    secret='...',
    # JWT claims to place in the token payload
    # this class takes care of providing the 'exp' (expiration time) key
    claims={
        'sub': '...'
    },
    # Time-To-Live, in seconds; default is 3600 (i.e., 1 hour)
    ttl=3600,
    # instead of waiting for it to actually expire,
    # renew the token whenever the remaining time-to-live is
    # less than this number of seconds; default is 60
    expiration_buffer=60,
    # signing algorithm to use; defaults to H256
    signing_algorithm='H256'
)

r = requests.get('http://example.com', auth=secret_auth)
```

## Development Setup

```bash
git clone git@github.com:umd-lib/requests-jwtauth.git
cd requests-jwtauth
pyenv install $(cat .python-version) --skip-existing
python -m venv .venv --prompt "requests-jwtauth-py$(cat .python-version)"
source .venv/bin/activate
pip install -e .[test]
```

#### Testing

Using [pytest]:

```bash
pytest
```

With [test coverage] information:

```bash
pytest --cov-report=term-missing --cov src
```

[Requests]: https://pypi.org/project/requests/
[AuthBase]: https://docs.python-requests.org/en/latest/user/authentication/#new-forms-of-authentication
[JWCrypto]: https://pypi.org/project/jwcrypto/
[JWT]: https://datatracker.ietf.org/doc/html/rfc7519
[JWT claims]: https://datatracker.ietf.org/doc/html/rfc7519#section-4
[pytest]: https://docs.pytest.org/en/latest/
[test coverage]: https://pytest-cov.readthedocs.io/en/latest/
