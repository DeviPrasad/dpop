#!/usr/bin/python3

"""
OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)
https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-12.html#name-dpop-access-token-request
5. DPoP Access Token Request
(Figure 4: Token Request for a DPoP sender-constrained token using an authorization code)

{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256"
  }
}
.
{
  "jti": "-BwC3ESc6acc2lTc",
  "htm": "POST",
  "htu": "https://server.example.com/token",
  "iat": 1562262616
}

The JWK in the token request:
{
	"kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256"
}

Lexicographically ordered keys of the JWK
{
    "crv": "P-256"
	"kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
}

Packed Representation:
The next step is to construct a JSON object containing only the required members of the
JWK representing the key and with no whitespace or line breaks before or after any
syntactic elements and with the required members ordered lexicographically by the 
Unicode code points of the member names.

{"crv":"P-256","kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}

"""

import hashlib
import base64
raw_ec_jwk=r'{"crv":"P-256","kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}'
s256 = hashlib.sha256()
s256.update(bytes(raw_ec_jwk, "utf-8"))
jwk_thumbprint = base64.urlsafe_b64encode(s256.digest()).rstrip(b'=')
assert(jwk_thumbprint == b'0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I')

