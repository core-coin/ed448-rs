use pbkdf2::pbkdf2_hmac;
use sha3::Sha3_512;

use crate::goldilocks::{ed448_derive_public, ed448_sign, secret_to_public, PrivateKey, PublicKey};

pub type ExtendedPrivate = [u8; 114];
pub type ExtendedPublic = [u8; 114];

pub fn hex_to_extended_private(str: &str) -> ExtendedPrivate {
    let mut p: ExtendedPrivate = [0; 114];
    hex::decode_to_slice(str, &mut p).expect("Decoding failed");

    p
}

pub fn extended_private_to_hex(p: &ExtendedPrivate) -> String {
    hex::encode(&p)
}

pub fn sha512_hash(password: &[u8], salt: &[u8]) -> [u8; 57] {
    let mut result = [0u8; 57];
    pbkdf2_hmac::<Sha3_512>(password, salt, 2048, &mut result);

    result
}

pub fn seed_to_extended_private(seed: &[u8]) -> ExtendedPrivate {
    if seed.len() != 64 {
        panic!("Seed must be 64 bytes");
    }
    let mut key: ExtendedPrivate = [0u8; 114];
    let mut result = sha512_hash(seed, b"mnemonicforthechain");
    key[0..57].clone_from_slice(&result);
    
    result = sha512_hash(seed, b"mnemonicforthekey");
    key[57..114].clone_from_slice(&result);

    key[113] |= 0x80;
    key[112] |= 0x80;
    key[112] &= 0xbf;

    key
}

pub fn to_public(key: &ExtendedPrivate) -> PublicKey {
    let mut secret: PrivateKey = [0u8; 57];
    secret.copy_from_slice(&key[57..114]);
    let public: PublicKey = secret_to_public(&secret);

    public
}

pub fn extended_private_to_public(key: &ExtendedPrivate) -> ExtendedPublic {
    let mut extended_public: ExtendedPublic = [0u8; 114];
    extended_public[0..57].copy_from_slice(&key[0..57]);
    let public = to_public(&key);
    extended_public[57..114].copy_from_slice(&public);

    extended_public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_encode_decode() {
        let s1: &str = "757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99";
        let key: ExtendedPrivate = hex_to_extended_private(&s1);

        assert_eq!(s1, extended_private_to_hex(&key));
    }

    #[test]
    #[should_panic(expected = "Decoding failed")]
    pub fn test_serialize_panic() {
        let s: &str = "00";
        hex_to_extended_private(&s);
    }

    #[test]
    pub fn test_key_from_seed() {
        let mut seed = [0u8; 64];
        hex::decode_to_slice("6bc0169565eecbc8e62259959534a67684adbd4c229cc8830405fe81f60c7b896a273421c9587f4b3321ab8353bf7178b8f383ce07f916de7abebabfef0f5fee", &mut seed).expect("Decode error");

        let key: ExtendedPrivate = seed_to_extended_private(&seed);
        assert_eq!(
            "348728c67f8827c5fac17c81c17cba245c957ee16d115def1802cb39d637fb682047b054f3eb4b169477d845b3b4d7c87fa36ec3e7e98d0c0361f1dc6767753ca9db7ed41c32a745d7930121feba01b9b9ad0a6774dc906e8775c3eedb26037e4c2ffceccc198df6f97f9c7f2d79b89baf85",
            extended_private_to_hex(&key)           
        );
    }

    #[test]
    pub fn test_extended_pivate_to_public() {
        let prv: ExtendedPrivate = hex_to_extended_private("004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594");
        let public: ExtendedPublic = extended_private_to_public(&prv);
        assert_eq!(
            "004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0db615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880",
            extended_private_to_hex(&public)
        );
    }

}
