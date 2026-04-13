"""OAuth 2.0 / OIDC provider integration — Okta, Auth0, Google."""
from __future__ import annotations

import json
import time
import urllib.parse
import uuid
from typing import Any, Dict, Optional, Tuple
from urllib import request, error


PROVIDER_CONFIGS = {
    "okta": {
        "auth_url_template": "https://{domain}/oauth2/v1/authorize",
        "token_url_template": "https://{domain}/oauth2/v1/token",
        "userinfo_url_template": "https://{domain}/oauth2/v1/userinfo",
        "jwks_url_template": "https://{domain}/oauth2/v1/keys",
    },
    "auth0": {
        "auth_url_template": "https://{domain}/authorize",
        "token_url_template": "https://{domain}/oauth/token",
        "userinfo_url_template": "https://{domain}/userinfo",
        "jwks_url_template": "https://{domain}/.well-known/jwks.json",
    },
    "google": {
        "auth_url_template": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url_template": "https://oauth2.googleapis.com/token",
        "userinfo_url_template": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_url_template": "https://www.googleapis.com/oauth2/v3/certs",
    },
}


class OAuthProvider:
    """
    OAuth 2.0 / OIDC provider integration.

    Usage::

        provider = OAuthProvider(
            provider="google",
            client_id="your-client-id",
            client_secret="your-client-secret",
            redirect_uri="https://app.example.com/auth/callback",
        )
        auth_url = provider.get_auth_url()
        # Redirect user to auth_url ...
        user_info = await provider.exchange_code(code="auth-code")
    """

    def __init__(
        self,
        provider: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        domain: Optional[str] = None,
        scopes: Optional[list] = None,
    ) -> None:
        self.provider = provider.lower()
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.domain = domain or ""
        self.scopes = scopes or ["openid", "email", "profile"]

        if self.provider not in PROVIDER_CONFIGS:
            raise ValueError(f"Unknown provider: {provider}. Supported: {list(PROVIDER_CONFIGS)}")

        config = PROVIDER_CONFIGS[self.provider]
        self._auth_url = config["auth_url_template"].format(domain=domain)
        self._token_url = config["token_url_template"].format(domain=domain)
        self._userinfo_url = config["userinfo_url_template"].format(domain=domain)
        self._jwks_url = config["jwks_url_template"].format(domain=domain)

    def get_auth_url(self, state: Optional[str] = None) -> Tuple[str, str]:
        """
        Get the authorization URL to redirect users to.
        Returns (url, state).
        """
        state = state or str(uuid.uuid4())
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": str(uuid.uuid4()),
        }
        url = self._auth_url + "?" + urllib.parse.urlencode(params)
        return url, state

    def exchange_code(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }).encode("utf-8")

        req = request.Request(
            self._token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user info from the provider's userinfo endpoint."""
        req = request.Request(
            self._userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def get_jwks(self) -> Dict[str, Any]:
        """Fetch the provider's JWKS (JSON Web Key Set) for token verification."""
        with request.urlopen(self._jwks_url, timeout=10) as resp:
            return json.loads(resp.read())
