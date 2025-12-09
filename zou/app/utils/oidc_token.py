import time
import requests
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError
from zou.app import config

# Cache global pour éviter d'appeler Keycloak en boucle
JWKS_CACHE = {
    "last_fetch": 0,
    "jwks_client": None
}

def get_jwks_client():
    global JWKS_CACHE

    # Refresh JWKS toutes les 5 minutes
    if JWKS_CACHE["jwks_client"] is None or (time.time() - JWKS_CACHE["last_fetch"]) > 300:
        discovery_url = f"{config.OIDC_ISSUER}/.well-known/openid-configuration"
        oidc_conf = requests.get(discovery_url).json()

        jwks_uri = oidc_conf["jwks_uri"]
        JWKS_CACHE["jwks_client"] = PyJWKClient(jwks_uri)
        JWKS_CACHE["last_fetch"] = time.time()

    return JWKS_CACHE["jwks_client"]


def decode_and_verify_kc_token(token: str) -> dict:
    """
    Vérifie cryptographiquement un token OIDC Keycloak (RS256)
    et renvoie son payload décodé.
    """

    jwks_client = get_jwks_client()

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as e:
        raise InvalidTokenError(f"Cannot get signing key: {e}")

    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.OIDC_CLIENT_ID,  # Vérifie que le token est destiné à Kitsu
            issuer=config.OIDC_ISSUER,       # Vérifie la provenance
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            }
        )
    except InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid Keycloak token: {e}")

    return payload
