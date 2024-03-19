use pbkdf2::pbkdf2_hmac;
use sha3::Sha3_512;

use crate::{extended_point::{add_extended_to_extended, eddsa_like_decode, precomputed_scalar_mul}, goldilocks::{ed448_derive_public, ed448_sign, secret_to_public, PrivateKey, PublicKey}, scalar::{decode_long, halve}};

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

fn concatenate_and_hex(prefix: u8, key: &[u8], index: u32, salt: &[u8]) -> [u8; 57] {
    if key.len() != 57 {
        panic!("Wrong key length");
    }

    let mut p: [u8; 62] = [0u8; 62];
    p[0] = prefix;
    p[1.. 58].copy_from_slice(&key[0..57]);

    let mut i = 58;
    let mut index_copy = index;
    while i < 62 {
        p[i] = (index_copy & 0xff) as u8;
        index_copy >>= 8;
        i += 1;
    };

    sha512_hash(&p, &salt)
}

fn add_two_secrets(secret1: &[u8], secret2: &[u8]) -> [u8; 57] {
    if secret1.len() != 57 || secret2.len() != 57 {
        panic!("Wrong key length");
    };

    let mut result: [u8; 57] = [0u8; 57];
    let mut count: u16 = 0;

    for i in 0..57 {
        count += secret1[i] as u16 + secret2[i] as u16;
        result[i] = (count & 0xff) as u8;
        count >>= 8;
    }

    result
}

fn shift_public(public: &[u8], shift: &[u8]) -> [u8; 57] {
    let mut r = decode_long(&shift);
    r = halve(r);
    r = halve(r);
    let p2 = precomputed_scalar_mul(r);

    let p1 = eddsa_like_decode(&public).expect("Decoding error");

    let p = add_extended_to_extended(&p1, &p2);

    p.eddsa_like_encode()

}

fn clamp_template(hash: &mut [u8]) {
    hash[56] = 0;
    hash[55] = 0;
    hash[54] = 0;
    hash[53] = 0;
    hash[0] &= 0xfc;
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

pub fn private_to_child_private(key: &ExtendedPrivate, index: u32) -> ExtendedPrivate {
    let mut child_key: ExtendedPrivate = [0u8; 114];

    if index >= 0x80000000 {
        let mut hash = concatenate_and_hex(1, &key[57..114], index, &key[0..57]);
        child_key[0..57].copy_from_slice(&hash[0..57]);

        hash = concatenate_and_hex(0, &key[57..114], index, &key[0..57]);
        clamp_template(&mut hash[..]);
        hash = add_two_secrets(&key[57..114], &hash);
        child_key[57..114].copy_from_slice(&hash[0..57]);
    } else {
        let mut private_key: [u8; 57] = [0u8; 57];
        private_key.copy_from_slice(&key[57..114]);
        let public_key = ed448_derive_public(&private_key);

        let mut hash = concatenate_and_hex(3, &public_key[0..57], index, &key[0..57]);
        child_key[0..57].copy_from_slice(&hash[0..57]);

        hash = concatenate_and_hex(2, &public_key[0..57], index, &key[0..57]);
        clamp_template(&mut hash[..]);
        hash = add_two_secrets(&key[57..114], &hash);
        child_key[57..114].copy_from_slice(&hash[0..57]);
    }

    child_key
}

pub fn public_to_child_public(key: &ExtendedPublic, index: u32) -> ExtendedPublic {
    if index >= 0x80000000 {
        panic!("Trying to derive hardhened key from public")
    }

    let mut child: ExtendedPublic = [0u8; 114];
    let mut hash = concatenate_and_hex(3, &key[57..114], index, &key[0..57]);
    child[0..57].copy_from_slice(&hash[0..57]);

    hash = concatenate_and_hex(2, &key[57..114], index, &key[0..57]);
    clamp_template(&mut hash);
    let mut public: PublicKey = [0u8; 57];
    public.copy_from_slice(&key[57..114]);
    let shifted_key = shift_public(&public, &hash);

    child[57..114].copy_from_slice(&shifted_key[0..57]);

    child
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

    #[test]
    pub fn test_pivate_to_child_private() {
        let mut parent_key = hex_to_extended_private("757a4a352e3aafdad7f65f6bf4f150800d334ffcac56e719cc3412ae6ae5a2f547f2b587785ac52c0136a09f05bbe43b6b000e3f9c49f7f7c76a103854fa8597b9514a0d6b11e0e972d492c0fd61afe5fb5baa38d51406ba333c7e5a7c43a121b694d6694047e6433e05c372a5eb78a48e99");
        let mut child_key = private_to_child_private(&parent_key, 0);

        assert_eq!(
            "b8254111ddf243fd897b44878678ff15d16763c7939e86512fd2b6d6535fde62ec6c94dd61fc76033d94e001ea26ef3950a0edd2ef74713760e63a36576ee565e08646a99c2062ebdf773167dc533a0a3a1b0d929d8b77b5faf7d54d557f3b537eeb572b04b04d246fb63154381679a48e99",
            extended_private_to_hex(&child_key)
        );

        parent_key = hex_to_extended_private("88b8592017482e0d85a8c405b84e12ba3a8ac552198216b0da811adc368589cc86a8bb38c67c766f9a942e7cedf5a6a36338f3d5bdd9466e2554b229028a76f79a18f4171fea287db096f05cc62ff3246ec70a2ebbf896b094350650846703183c09a13790e93fd3110c3ec0fe338daf93ba");
        child_key = private_to_child_private(&parent_key, 0x80000000);

        assert_eq!(
            "bd9c963ce9ac0fb9da7f9dfa0ea84251ed6f3eba924858bb7b2f9eb3a66aa4fb42a87a0d5b05c9a48c442b480477d17cd89b8679acd6ccdf02fca262c2f9a158d51bea28d0b2724f237560f65a3b8ae98215dc97ade43beb1e3dad4fc12ec8a81da661db0ab6b94f1c566e38f16e8daf93ba",
            extended_private_to_hex(&child_key)
        );
    }

    #[test]
    pub fn test_public_to_child_public() {
        let parent_key = hex_to_extended_private("08288c75a01cafb05193567fb285b66767a6d393b7763f3f085f140ac0ad59b56dfdae70533f112a67cbd359910b2c5f1c8916bf6f593a5db4e7e1d0e85a354edc803d39f89923aadd362da91693cbb01206b86b3173039e18513a9964f96f34aa27b275d9a81b50905ebc860905e1c51700");
        let child_key = public_to_child_public(&parent_key, 0);

        assert_eq!(
            "0c051354b0efede7fa00124dd9e5a37bb7f0edf157b8139f64be5f6cac2c5edc7c60e1c4245136e9b9b8ea7f9ef5ab20032f6c6f2dba07d7f44a5aa538883ce7a9115337293eedb620ee031b71e994936557e58ef1dbafd1f91413c154b8713c43150a14e11c0ce0ba1d6d55bd26802d2080",
            extended_private_to_hex(&child_key)
        );
    }
}
