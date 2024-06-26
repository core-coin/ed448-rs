#![allow(clippy::should_implement_trait)]
mod bignumber;
mod constants32;
mod decaf_combs_32;
mod decaf_wnaf_table;
mod eddsa;
pub mod errors;
mod extended_point;
pub mod goldilocks;
mod karatsuba_32;
mod karatsuba_square_32;
mod scalar;

use crate::errors::LibgoldilockErrors;
use goldilocks::{ed448_derive_public, ed448_sign, hex_to_private_key};
use rand::{CryptoRng, Rng};
use serdect::serde::{de, ser, Deserialize, Serialize};

pub trait PrehashSigner<S> {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<S, LibgoldilockErrors>;
}

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct SecretKey {
    key: [u8; 57],
}

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct VerifyingKey {
    key: [u8; 57],
}

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct SigningKey {
    secret_key: SecretKey,
    verifying_key: VerifyingKey,
}

pub struct Signature {
    sig: [u8; 171],
}

impl SecretKey {
    pub fn from_str(str: &str) -> Self {
        let key = hex_to_private_key(str);

        Self { key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            key: bytes.try_into().expect("ED448: Wrong Private Key Length"),
        }
    }
}

impl From<SecretKey> for SigningKey {
    fn from(s: SecretKey) -> SigningKey {
        SigningKey::from_slice(&s.key)
    }
}

impl VerifyingKey {
    pub fn from_str(str: &str) -> Self {
        let key = hex_to_private_key(str);

        Self { key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { key: bytes.try_into().expect("ED448: Wrong Public Key Length")}
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl SigningKey {
    pub fn from_str(str: &str) -> Self {
        let private_key = hex_to_private_key(str);
        let public_key = ed448_derive_public(&private_key);
        let secret_key = SecretKey { key: private_key };
        let verifying_key = VerifyingKey { key: public_key };

        Self {
            secret_key,
            verifying_key,
        }
    }

    /// # Panics
    ///
    /// This function will panic if the slice is not exactly 57 bytes
    pub fn from_slice(s: &[u8]) -> Self {
        let mut private_key: [u8; 57] = [0; 57];
        private_key.copy_from_slice(s);
        let public_key = ed448_derive_public(&private_key);
        let secret_key = SecretKey { key: private_key };
        let verifying_key = VerifyingKey { key: public_key };

        Self {
            secret_key,
            verifying_key,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Result<Self, LibgoldilockErrors> {
        let mut private_key: [u8; 57] = [0; 57];

        if s.len() != 57 {
            return Err(LibgoldilockErrors::InvalidPrivKeyLengthErrro(s.len()))
        }

        private_key.copy_from_slice(s);
        let public_key = ed448_derive_public(&private_key);
        let secret_key = SecretKey { key: private_key };
        let verifying_key = VerifyingKey { key: public_key };

        Ok(Self {
            secret_key,
            verifying_key,
        })
    }

    pub fn random<R>(rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let mut key: [u8; 57] = [0; 57];
        rng.fill_bytes(key.as_mut_slice());

        SigningKey::from_slice(&key)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn to_bytes(&self) -> [u8; 57] {
        self.secret_key.key
    }
}

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature, LibgoldilockErrors> {
        let sig = ed448_sign(&self.secret_key.key, prehash);
        let mut sig_with_private_key: [u8; 171] = [0; 171];
        sig_with_private_key[0..114].copy_from_slice(&sig);
        sig_with_private_key[114..171].copy_from_slice(&self.verifying_key.key);

        Ok(Signature {
            sig: sig_with_private_key,
        })
    }
}

impl Signature {
    pub fn as_slice(&self) -> &[u8] {
        &self.sig
    }
}

impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let s = hex::encode(&self.secret_key.key);
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Ok(SigningKey::from_str(&s))
        } else {
            Err(de::Error::custom("Expected a string"))
        }
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let s = hex::encode(&self.key);
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Ok(SecretKey::from_str(&s))
        } else {
            Err(de::Error::custom("Expected a string"))
        }
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let s = hex::encode(&self.key);
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Ok(VerifyingKey::from_str(&s))
        } else {
            Err(de::Error::custom("Expected a string"))
        }
    }
}

mod tests {
    use crate::{SecretKey, SigningKey, VerifyingKey};

    #[test]
    fn test_secret_key_serde() {
        let key = SecretKey::from_str("010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101");
        let serialized = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serialized,
            r#""010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101""#
        );

        let deserialized: SecretKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_verifying_key_serde() {
        let key = VerifyingKey::from_str("010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101");
        let serialized = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serialized,
            r#""010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101""#
        );

        let deserialized: VerifyingKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_signing_key_serde() {
        let key = SigningKey::from_str("010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101");
        let serialized = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serialized,
            r#""010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101""#
        );

        let deserialized: SigningKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_signing_key_from_bytes() {
        let key = SigningKey::from_bytes(&[1; 57]).unwrap();
        assert_eq!(key.secret_key().key, [1; 57]);
    }
}
