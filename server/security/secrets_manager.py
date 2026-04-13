"""Secrets manager — AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager."""
from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SecretsBackend(ABC):
    """Abstract secrets backend."""

    @abstractmethod
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve a secret value by name."""

    @abstractmethod
    def set_secret(self, secret_name: str, value: str) -> bool:
        """Store or update a secret."""

    @abstractmethod
    def delete_secret(self, secret_name: str) -> bool:
        """Delete a secret."""


class EnvSecretsBackend(SecretsBackend):
    """Read secrets from environment variables (default/fallback)."""

    def get_secret(self, secret_name: str) -> Optional[str]:
        return os.environ.get(secret_name)

    def set_secret(self, secret_name: str, value: str) -> bool:
        os.environ[secret_name] = value
        return True

    def delete_secret(self, secret_name: str) -> bool:
        if secret_name in os.environ:
            del os.environ[secret_name]
            return True
        return False


class AWSSecretsManagerBackend(SecretsBackend):
    """AWS Secrets Manager backend."""

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        self._client = None

    def _get_client(self):
        if not self._client:
            import boto3
            self._client = boto3.client("secretsmanager", region_name=self.region)
        return self._client

    def get_secret(self, secret_name: str) -> Optional[str]:
        try:
            response = self._get_client().get_secret_value(SecretId=secret_name)
            return response.get("SecretString") or response.get("SecretBinary", b"").decode()
        except Exception as e:
            logger.error("AWS SecretManager get_secret error: %s", e)
            return None

    def set_secret(self, secret_name: str, value: str) -> bool:
        try:
            client = self._get_client()
            try:
                client.put_secret_value(SecretId=secret_name, SecretString=value)
            except client.exceptions.ResourceNotFoundException:
                client.create_secret(Name=secret_name, SecretString=value)
            return True
        except Exception as e:
            logger.error("AWS SecretManager set_secret error: %s", e)
            return False

    def delete_secret(self, secret_name: str) -> bool:
        try:
            self._get_client().delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
            return True
        except Exception as e:
            logger.error("AWS SecretManager delete_secret error: %s", e)
            return False


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault backend using KV v2."""

    def __init__(self, vault_addr: str, token: str, mount: str = "secret") -> None:
        self.vault_addr = vault_addr.rstrip("/")
        self.token = token
        self.mount = mount

    def get_secret(self, secret_name: str) -> Optional[str]:
        from urllib import request, error
        url = f"{self.vault_addr}/v1/{self.mount}/data/{secret_name}"
        req = request.Request(url, headers={"X-Vault-Token": self.token})
        try:
            with request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return json.dumps(data.get("data", {}).get("data", {}))
        except Exception as e:
            logger.error("Vault get_secret error: %s", e)
            return None

    def set_secret(self, secret_name: str, value: str) -> bool:
        from urllib import request as urlrequest
        url = f"{self.vault_addr}/v1/{self.mount}/data/{secret_name}"
        payload = json.dumps({"data": {"value": value}}).encode()
        req = urlrequest.Request(
            url, data=payload,
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlrequest.urlopen(req, timeout=5):
                return True
        except Exception as e:
            logger.error("Vault set_secret error: %s", e)
            return False

    def delete_secret(self, secret_name: str) -> bool:
        from urllib import request as urlrequest
        url = f"{self.vault_addr}/v1/{self.mount}/metadata/{secret_name}"
        req = urlrequest.Request(url, headers={"X-Vault-Token": self.token}, method="DELETE")
        try:
            with urlrequest.urlopen(req, timeout=5):
                return True
        except Exception as e:
            logger.error("Vault delete_secret error: %s", e)
            return False


class SecretsManager:
    """
    Unified secrets manager that delegates to a configured backend.

    Usage::

        mgr = SecretsManager(backend="aws", region="us-east-1")
        db_password = mgr.get("DB_PASSWORD")
    """

    def __init__(
        self,
        backend: str = "env",
        **kwargs: Any,
    ) -> None:
        if backend == "aws":
            self._backend: SecretsBackend = AWSSecretsManagerBackend(**kwargs)
        elif backend == "vault":
            self._backend = VaultSecretsBackend(**kwargs)
        else:
            self._backend = EnvSecretsBackend()

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self._backend.get_secret(name) or default

    def set(self, name: str, value: str) -> bool:
        return self._backend.set_secret(name, value)

    def delete(self, name: str) -> bool:
        return self._backend.delete_secret(name)
