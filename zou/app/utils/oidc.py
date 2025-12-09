from authlib.integrations.requests_client import OAuth2Session
from zou.app import config
import requests

def get_provider_config():
    discovery_url = f"{config.OIDC_ISSUER}/.well-known/openid-configuration"
    return requests.get(discovery_url).json()

def get_oidc_session(state=None):
    provider_cfg = get_provider_config()
    return OAuth2Session(
        client_id=config.OIDC_CLIENT_ID,
        client_secret=config.OIDC_CLIENT_SECRET,
        scope="openid email profile",
        redirect_uri=config.OIDC_REDIRECT_URI,
        state=state
    ), provider_cfg
