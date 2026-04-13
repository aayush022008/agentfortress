# SSO Setup Guide — AgentShield

AgentShield supports SAML 2.0 and OAuth 2.0/OIDC for Single Sign-On.

## Supported Providers

- **Okta** — SAML 2.0 and OIDC
- **Auth0** — OIDC
- **Google Workspace** — OIDC
- **Azure Active Directory** — SAML 2.0 and OIDC
- **Any SAML 2.0 IdP**

## OAuth 2.0 / OIDC Setup (Google Example)

1. In Google Cloud Console, create an OAuth 2.0 Client ID.
2. Set **Authorized redirect URI**: `https://your-agentshield-domain/auth/callback`
3. In AgentShield admin settings, configure:
   ```json
   {
     "provider": "google",
     "client_id": "your-google-client-id",
     "client_secret": "your-google-client-secret",
     "redirect_uri": "https://your-domain/auth/callback"
   }
   ```
4. Enable SSO in Organization Settings → Authentication.

## SAML 2.0 Setup (Okta Example)

1. In Okta Admin, create a new SAML 2.0 app.
2. Configure:
   - **Single sign on URL**: `https://your-domain/auth/saml/callback`
   - **Audience URI (SP Entity ID)**: `https://your-domain`
3. Download the IdP metadata XML or note the SSO URL.
4. In AgentShield, provide:
   - IdP SSO URL
   - IdP Entity ID
   - IdP Certificate (PEM)
5. Provide users with the SP metadata from `/auth/saml/metadata`.

## SCIM Provisioning

AgentShield supports SCIM 2.0 for automated user provisioning:
- Endpoint: `https://your-domain/scim/v2`
- Bearer token: Generate in Admin → API Keys

## Mapping IdP Groups to AgentShield Roles

In SSO configuration, add group mappings:
```json
{
  "group_mappings": {
    "security-admins": "admin",
    "security-analysts": "analyst",
    "developers": "viewer"
  }
}
```
