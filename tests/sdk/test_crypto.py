"""Tests for cryptographic security modules."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.crypto.signing import EventSigner, SignedEvent
from agentshield.crypto.encryption import FieldEncryptor
from agentshield.crypto.key_manager import KeyManager, KeyVersion


class TestEventSigner:
    def test_sign_and_verify(self):
        signer = EventSigner.generate()
        event = {"event_type": "tool_call", "tool": "bash", "session_id": "s-001"}
        signed = signer.sign(event)
        assert signer.verify(signed)

    def test_tampered_event_fails(self):
        signer = EventSigner.generate()
        event = {"event_type": "tool_call", "tool": "bash"}
        signed = signer.sign(event)
        # Tamper with the payload
        signed.payload["tool"] = "malicious_tool"
        assert not signer.verify(signed)

    def test_export_import_keys(self):
        signer = EventSigner.generate()
        private_pem = signer.export_private_key_pem()
        pub_pem = signer.export_public_key_pem()

        # Reload from PEM
        signer2 = EventSigner.from_pem(private_pem)
        event = {"test": "data"}
        signed = signer2.sign(event)
        assert signer2.verify(signed)

    def test_public_key_verifier(self):
        signer = EventSigner.generate()
        pub_pem = signer.export_public_key_pem()
        verifier = EventSigner.verifier_from_public_pem(pub_pem)
        event = {"event": "login", "user": "alice"}
        signed = signer.sign(event)
        assert verifier.verify(signed)

    def test_signed_event_serialization(self):
        signer = EventSigner.generate()
        event = {"event_type": "alert", "severity": "high"}
        signed = signer.sign(event)
        d = signed.to_dict()
        assert "payload" in d
        assert "signature" in d
        assert "public_key" in d
        reconstructed = SignedEvent.from_dict(d)
        assert signer.verify(reconstructed)


class TestFieldEncryptor:
    def test_encrypt_decrypt(self):
        enc = FieldEncryptor.generate()
        plaintext = "sensitive data 12345"
        ciphertext = enc.encrypt(plaintext)
        assert ciphertext != plaintext
        assert ciphertext.startswith("enc:aes256gcm:")
        decrypted = enc.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_fields(self):
        enc = FieldEncryptor.generate()
        record = {"name": "Alice", "ssn": "123-45-6789", "age": 30}
        encrypted = enc.encrypt_fields(record, fields=["ssn"])
        assert encrypted["name"] == "Alice"
        assert encrypted["ssn"].startswith("enc:aes256gcm:")
        decrypted = enc.decrypt_fields(encrypted, fields=["ssn"])
        assert decrypted["ssn"] == "123-45-6789"

    def test_export_import_key(self):
        enc = FieldEncryptor.generate()
        key_b64 = enc.export_key_b64()
        enc2 = FieldEncryptor.from_base64(key_b64)
        ciphertext = enc.encrypt("test value")
        assert enc2.decrypt(ciphertext) == "test value"

    def test_wrong_key_fails(self):
        enc1 = FieldEncryptor.generate()
        enc2 = FieldEncryptor.generate()
        ciphertext = enc1.encrypt("secret")
        with pytest.raises(Exception):
            enc2.decrypt(ciphertext)

    def test_encrypt_json(self):
        enc = FieldEncryptor.generate()
        data = {"user": "alice", "roles": ["admin"], "score": 42}
        ciphertext = enc.encrypt_json(data)
        decrypted = enc.decrypt_json(ciphertext)
        assert decrypted == data


class TestKeyManager:
    def test_initialize_and_use(self, tmp_path):
        keystore = str(tmp_path / "keys.json")
        mgr = KeyManager(keystore_path=keystore)
        mgr.initialize()
        enc = mgr.get_encryptor()
        ct = enc.encrypt("test secret")
        pt = enc.decrypt(ct)
        assert pt == "test secret"

    def test_rotate_keys(self, tmp_path):
        keystore = str(tmp_path / "keys.json")
        mgr = KeyManager(keystore_path=keystore)
        mgr.initialize()

        # Encrypt with original key
        enc_v1 = mgr.get_encryptor()
        ct = enc_v1.encrypt("pre-rotation secret")

        # Rotate
        new_kv = mgr.rotate()
        assert new_kv.version == 2

        # Decrypt with any version
        pt = mgr.decrypt_any(ct)
        assert pt == "pre-rotation secret"

    def test_list_versions(self, tmp_path):
        keystore = str(tmp_path / "keys.json")
        mgr = KeyManager(keystore_path=keystore)
        mgr.initialize()
        mgr.rotate()
        versions = mgr.list_versions()
        assert len(versions) == 2
        active = [v for v in versions if v.active]
        assert len(active) == 1
        assert active[0].version == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
