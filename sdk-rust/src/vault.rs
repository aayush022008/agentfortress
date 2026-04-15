//! Vault — Encrypted Secrets Manager

use std::collections::HashMap;
use chrono::Utc;
use uuid::Uuid;

pub struct SecretEntry {
    pub secret_id: String,
    pub name: String,
    pub value_encrypted: Vec<u8>,
    pub created_at: f64,
    pub last_accessed: f64,
    pub access_count: u32,
    pub tags: Vec<String>,
    pub expiry: Option<f64>,
}

pub struct VaultToken {
    pub token: String,
    pub secret_id: String,
    pub issued_at: f64,
    pub expires_at: f64,
    pub single_use: bool,
}

pub struct Vault {
    master_key: Vec<u8>,
    secrets: HashMap<String, SecretEntry>,
    name_index: HashMap<String, String>,
    tokens: HashMap<String, VaultToken>,
}

impl Vault {
    pub fn new(master_key: Option<Vec<u8>>) -> Self {
        let key = master_key.unwrap_or_else(|| {
            // Generate a key from timestamp bytes + fixed salt
            let ts = Utc::now().timestamp_millis() as u64;
            let salt: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
            let mut key = [0u8; 32];
            let ts_bytes = ts.to_le_bytes();
            for i in 0..32 {
                key[i] = ts_bytes[i % 8] ^ salt[i % 8] ^ (i as u8);
            }
            key.to_vec()
        });
        Self {
            master_key: key,
            secrets: HashMap::new(),
            name_index: HashMap::new(),
            tokens: HashMap::new(),
        }
    }

    pub fn store(&mut self, name: &str, value: &str, tags: Vec<String>, ttl_seconds: Option<f64>) -> String {
        let secret_id = Self::generate_id();
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let expiry = ttl_seconds.map(|ttl| now + ttl);
        let encrypted = Self::xor_encrypt(value.as_bytes(), &self.master_key);

        let entry = SecretEntry {
            secret_id: secret_id.clone(),
            name: name.to_string(),
            value_encrypted: encrypted,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            tags,
            expiry,
        };

        self.name_index.insert(name.to_string(), secret_id.clone());
        self.secrets.insert(secret_id.clone(), entry);
        secret_id
    }

    pub fn get(&mut self, secret_id: &str) -> Result<String, String> {
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let entry = self.secrets.get_mut(secret_id)
            .ok_or_else(|| format!("Secret not found: {}", secret_id))?;

        if let Some(expiry) = entry.expiry {
            if now > expiry {
                return Err(format!("Secret expired: {}", secret_id));
            }
        }

        entry.last_accessed = now;
        entry.access_count += 1;
        let decrypted = Self::xor_encrypt(&entry.value_encrypted, &self.master_key.clone());
        String::from_utf8(decrypted).map_err(|e| e.to_string())
    }

    pub fn get_by_name(&mut self, name: &str) -> Result<String, String> {
        let secret_id = self.name_index.get(name)
            .ok_or_else(|| format!("Secret not found by name: {}", name))?
            .clone();
        self.get(&secret_id)
    }

    pub fn issue_token(&mut self, secret_id: &str, ttl_seconds: f64, single_use: bool) -> Result<VaultToken, String> {
        if !self.secrets.contains_key(secret_id) {
            return Err(format!("Secret not found: {}", secret_id));
        }
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let token = VaultToken {
            token: Self::generate_id(),
            secret_id: secret_id.to_string(),
            issued_at: now,
            expires_at: now + ttl_seconds,
            single_use,
        };
        let tok = token.token.clone();
        let result = VaultToken {
            token: tok.clone(),
            secret_id: token.secret_id.clone(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            single_use: token.single_use,
        };
        self.tokens.insert(tok, token);
        Ok(result)
    }

    pub fn redeem_token(&mut self, token: &str) -> Result<String, String> {
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let (secret_id, single_use) = {
            let vt = self.tokens.get(token)
                .ok_or_else(|| "Token not found or already used".to_string())?;
            if now > vt.expires_at {
                return Err("Token expired".to_string());
            }
            (vt.secret_id.clone(), vt.single_use)
        };
        if single_use {
            self.tokens.remove(token);
        }
        self.get(&secret_id)
    }

    pub fn revoke(&mut self, secret_id: &str) -> bool {
        if let Some(entry) = self.secrets.remove(secret_id) {
            self.name_index.remove(&entry.name);
            self.tokens.retain(|_, v| v.secret_id != secret_id);
            true
        } else {
            false
        }
    }

    pub fn scan_for_leaks(&mut self, text: &str) -> Vec<String> {
        let mut leaked = Vec::new();
        // Collect all secret values first
        let secret_ids: Vec<String> = self.secrets.keys().cloned().collect();
        for id in secret_ids {
            if let Ok(value) = self.get(&id) {
                if !value.is_empty() && text.contains(&value) {
                    leaked.push(id);
                }
            }
        }
        leaked
    }

    pub fn purge_expired(&mut self) {
        let now = Utc::now().timestamp_millis() as f64 / 1000.0;
        let expired: Vec<String> = self.secrets.iter()
            .filter(|(_, e)| e.expiry.map(|exp| now > exp).unwrap_or(false))
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.revoke(&id);
        }
        // Purge expired tokens
        self.tokens.retain(|_, v| now <= v.expires_at);
    }

    fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
    }

    fn generate_id() -> String {
        Uuid::new_v4().to_string()
    }
}
