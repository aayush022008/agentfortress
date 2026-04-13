"""SAML 2.0 SSO support."""
from __future__ import annotations

import base64
import uuid
import zlib
from typing import Any, Dict, Optional
from urllib.parse import urlencode


class SAMLProvider:
    """
    SAML 2.0 Service Provider implementation.

    Usage::

        saml = SAMLProvider(
            idp_sso_url="https://idp.example.com/sso/saml",
            idp_entity_id="https://idp.example.com",
            sp_entity_id="https://agentshield.yourdomain.com",
            sp_acs_url="https://agentshield.yourdomain.com/auth/saml/callback",
        )
        redirect_url = saml.get_login_url()
        # Redirect user to redirect_url ...
        user = saml.process_response(saml_response_b64)
    """

    def __init__(
        self,
        idp_sso_url: str,
        idp_entity_id: str,
        sp_entity_id: str,
        sp_acs_url: str,
        idp_cert: Optional[str] = None,
        sp_private_key: Optional[str] = None,
        sp_cert: Optional[str] = None,
        name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    ) -> None:
        self.idp_sso_url = idp_sso_url
        self.idp_entity_id = idp_entity_id
        self.sp_entity_id = sp_entity_id
        self.sp_acs_url = sp_acs_url
        self.idp_cert = idp_cert
        self.sp_private_key = sp_private_key
        self.sp_cert = sp_cert
        self.name_id_format = name_id_format

    def get_login_url(self, relay_state: Optional[str] = None) -> str:
        """Build the SAML SSO redirect URL."""
        request_id = f"id_{uuid.uuid4().hex}"
        import datetime
        issue_instant = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = f"""<?xml version="1.0"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.idp_sso_url}"
    AssertionConsumerServiceURL="{self.sp_acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>{self.sp_entity_id}</saml:Issuer>
  <samlp:NameIDPolicy
      Format="{self.name_id_format}"
      AllowCreate="true"/>
</samlp:AuthnRequest>"""

        compressed = zlib.compress(authn_request.encode("utf-8"))[2:-4]
        encoded = base64.b64encode(compressed).decode("ascii")

        params: Dict[str, str] = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state

        return self.idp_sso_url + "?" + urlencode(params)

    def process_response(self, saml_response_b64: str) -> Dict[str, Any]:
        """
        Process a SAML response from the IdP.
        Returns user attributes dict.
        Requires 'python3-saml' or 'pysaml2' for full signature validation.
        """
        try:
            response_xml = base64.b64decode(saml_response_b64).decode("utf-8")
            return self._parse_saml_response(response_xml)
        except Exception as e:
            raise ValueError(f"Failed to process SAML response: {e}")

    def get_sp_metadata(self) -> str:
        """Return the Service Provider metadata XML."""
        return f"""<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{self.sp_entity_id}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{self.sp_acs_url}"
        index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

    # ------------------------------------------------------------------

    def _parse_saml_response(self, xml: str) -> Dict[str, Any]:
        """Extract user info from SAML assertion XML (basic parsing)."""
        import re

        def extract(tag: str) -> Optional[str]:
            m = re.search(rf"<[^>]*{tag}[^>]*>([^<]+)<", xml)
            return m.group(1).strip() if m else None

        name_id = extract("NameID") or ""
        email = extract("Attribute Name=\"email\"") or name_id

        attributes: Dict[str, str] = {}
        for attr_match in re.finditer(r'Name="([^"]+)"[^>]*>.*?<AttributeValue[^>]*>([^<]+)</AttributeValue>', xml, re.DOTALL):
            attributes[attr_match.group(1)] = attr_match.group(2).strip()

        return {
            "name_id": name_id,
            "email": email,
            "attributes": attributes,
        }
