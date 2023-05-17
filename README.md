# requests-jwtauth

Authenticator plugins for [Requests] that support JWT bearer tokens.

## Dependencies

* Python 3.8+
* [Requests]
* [JWCrypto]

## Installation

```bash
pip install git+https://github.com/umd-lib/requests-jwtauth.git
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

```bash
pytest
```

With test coverage information:

```bash
pytest --cov-report=term-missing --cov src
```

[Requests]: https://pypi.org/project/requests/
[JWCrypto]: https://pypi.org/project/jwcrypto/
