use crate::{chaincodes::{private_to_child_private, public_to_child_public, seed_to_extended_private}, goldilocks::ed448_derive_public};
use ripemd::{Ripemd160, Digest};

const PRIVATE_MAINNET_VERSION: &str = "0658299c";
const PUBLIC_MAINNET_VERSION: &str = "06582f87";
const PRIVATE_TESTNET_VERSION: &str = "05e3c9a2";
const PUBLIC_TESTNET_VERSION: &str = "05e3cf8d";
const MAINNET: u8 = 0;
const DEVIN: u8 = 1;

pub struct XKey {
    key: [u8; 57],
    version: [u8; 4],
    child_number: [u8; 4],
    fingerprint: [u8; 4],
    chaincode: [u8; 57],
    depth: u8,
    is_private: bool
}

impl XKey {
    pub fn from_base_58(key_string: &str) -> XKey {
        let vector_key = bs58::decode(&key_string).into_vec().expect("Base58 decoding error");

        if vector_key.len() != 131 {
            panic!("Invalid serialized data");
        }

        let mut bytes_key: [u8; 131] = [0u8; 131];
        bytes_key[0..131].clone_from_slice(&vector_key.as_slice());

        let mut version: [u8; 4] = [0; 4];
        version[0..4].clone_from_slice(&bytes_key[0..4]);

        let mut depth: u8 = bytes_key[4];

        let mut fingerprint: [u8; 4] = [0; 4];
        fingerprint[0..4].clone_from_slice(&bytes_key[5..9]);

        let mut child_number: [u8; 4] = [0; 4];
        child_number[0..4].clone_from_slice(&bytes_key[9..13]);

        let mut chaincode: [u8; 57] = [0; 57];
        chaincode[0..57].clone_from_slice(&bytes_key[13..70]);

        let mut key: [u8; 57] = [0; 57];
        key[0..57].clone_from_slice(&bytes_key[70..127]);

        let is_private: bool;
        let v = hex::encode(&version);
        if v.as_str() == PRIVATE_MAINNET_VERSION || v.as_str() == PRIVATE_TESTNET_VERSION {
            is_private = true;
        } else if v.as_str() == PUBLIC_MAINNET_VERSION || v.as_str() == PUBLIC_TESTNET_VERSION {
            is_private = false;
        } else {
            panic!("Wrong network prefix");
        }

        // validate checksum

        return XKey {
            key: key,
            version: version,
            child_number: child_number,
            fingerprint: fingerprint,
            chaincode: chaincode,
            depth: depth,
            is_private: is_private
        }
    }

    pub fn to_base_58 (&self) -> String {
        let mut bytes_key: [u8; 131] = [0u8; 131];
        bytes_key[0..4].clone_from_slice(&self.version);
        bytes_key[4] = self.depth;
        bytes_key[5..9].clone_from_slice(&self.fingerprint);
        bytes_key[9..13].clone_from_slice(&self.child_number);
        bytes_key[13..70].clone_from_slice(&self.chaincode);
        bytes_key[70..127].clone_from_slice(&self.key);
        
        let chksm = hash_double_sha_256(&bytes_key[0..127]);
        let mut out: [u8; 32] = [0u8; 32];
        hex::decode_to_slice(chksm, &mut out[..]).expect("Decoding error");
        bytes_key[127..131].clone_from_slice(&out[0..4]);

        bs58::encode(bytes_key).into_string()
    }

    pub fn from_seed(seed: &[u8], network: u8) -> XKey {
        let extended_private = seed_to_extended_private(seed);

        let mut chaincode: [u8; 57] = [0u8; 57];
        let mut key: [u8; 57] = [0u8; 57];

        chaincode.clone_from_slice(&extended_private[0..57]);
        key.clone_from_slice(&extended_private[57..114]);

        let mut version: [u8; 4] = [0u8; 4];
        if network == MAINNET {
            let a = hex::decode(PRIVATE_MAINNET_VERSION).expect("Decode error");
            version[0..4].clone_from_slice(&a[0..4]);
        } else if network == DEVIN {
            let a = hex::decode(PRIVATE_TESTNET_VERSION).expect("Decode error");
            version[0..4].clone_from_slice(&a[0..4]);
        } else {
            panic!("Invalid network");
        }

        return XKey {
            key: key,
            version: version,
            child_number: [0u8; 4],
            fingerprint: [0u8; 4],
            chaincode: chaincode,
            depth: 0,
            is_private: true
        }
    }

    pub fn get_child(&self, index: u32) -> XKey {
        let mut extended_key: [u8; 114] = [0u8; 114];
        extended_key[0..57].clone_from_slice(&self.chaincode);
        extended_key[57..114].clone_from_slice(&self.key);
        if self.is_private {
            extended_key = private_to_child_private(&extended_key, index);
        } else {
            extended_key = public_to_child_public(&extended_key, index);
        }

        let mut chaincode: [u8; 57] = [0u8; 57];
        let mut key: [u8; 57] = [0u8; 57];
        chaincode.clone_from_slice(&extended_key[0..57]);
        key.clone_from_slice(&extended_key[57..114]);

        let mut public: [u8; 57] = [0u8; 57];
        if self.is_private {
            let mut private: [u8; 57] = [0u8; 57];
            private[..].clone_from_slice(&self.key[..]);
            public = ed448_derive_public(&private);
        } else {
            public[..].clone_from_slice(&self.key[..]);
        }
        let fingerprint = hash160(&public);

        let mut version: [u8; 4] = [0u8; 4];
        version.clone_from_slice(&self.version[0..4]);

        let mut child_number: [u8; 4] = [0u8; 4];
        let mut i = 4;
        let mut index1 = index;
        while i > 0 {
            child_number[i - 1] = (index1 % 256) as u8;
            index1 /= 256;
            i -= 1; 
        }

        println!("{:?}", key);

        return XKey {
            key: key,
            version: version,
            child_number: child_number,
            fingerprint: fingerprint,
            chaincode: chaincode,
            depth: self.depth + 1,
            is_private: self.is_private
        }
    }
}

fn hash_double_sha_256(b: &[u8]) -> String {
    let mut d: String = sha256::digest(b);
    
    let mut d_bytes = hex::decode(d).expect("Decode error");
    d = sha256::digest(d_bytes);

    d
}

fn hash160(b: &[u8]) -> [u8; 4]{
    let mut d: String = sha256::digest(b);
    let mut d_bytes = hex::decode(d).expect("Decode error");

    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(&d_bytes);
    let mut result: [u8; 4] = [0u8; 4];
    result.clone_from_slice(&hasher.finalize()[..4]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_xprv_decode() {
        let key = XKey::from_base_58("xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y");

        assert_eq!(key.key, [97, 241, 220, 103, 103, 117, 60, 169, 219, 126, 212, 28, 50, 167, 69, 215, 147, 1, 33, 254, 186, 1, 185, 185, 173, 10, 103, 116, 220, 144, 110, 135, 117, 195, 238, 219, 38, 3, 126, 76, 47, 252, 236, 204, 25, 141, 246, 249, 127, 156, 127, 45, 121, 184, 155, 175, 133]);
        assert_eq!(hex::encode(&key.version), PRIVATE_MAINNET_VERSION);
        assert_eq!(key.child_number, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(key.fingerprint, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(key.chaincode, [52, 135, 40, 198, 127, 136, 39, 197, 250, 193, 124, 129, 193, 124, 186, 36, 92, 149, 126, 225, 109, 17, 93, 239, 24, 2, 203, 57, 214, 55, 251, 104, 32, 71, 176, 84, 243, 235, 75, 22, 148, 119, 216, 69, 179, 180, 215, 200, 127, 163, 110, 195, 231, 233, 141, 12, 3]);
        assert_eq!(key.depth, 0);
        assert_eq!(key.is_private, true);
    }

    #[test]
    pub fn test_decode_encode() {
        let key_string = "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y";
        let encoded = XKey::from_base_58(key_string);
        let decoded = encoded.to_base_58();
        assert_eq!(key_string, decoded);
    }

    #[test]
    pub fn test_key_from_seed() {
        let seed_string = "6bc0169565eecbc8e62259959534a67684adbd4c229cc8830405fe81f60c7b896a273421c9587f4b3321ab8353bf7178b8f383ce07f916de7abebabfef0f5fee";
        let seed = &hex::decode(seed_string).expect("Decode error")[0..64];
        let key = XKey::from_seed(&seed, MAINNET);
        assert_eq!(
            "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y",
            key.to_base_58()
        );
    }

    #[test]
    pub fn test_child_xpriv() {
        let xpriv_string = "xprv44jU3WStrxLpqTPjfJhEm5YWSnxHXWT1nxAz2LZucufEACdLtu2kbMFhkrHk4QzY3VNv1J4JpL9KQykmWeAaacHkL9azdG1uxDzG9cip6ngsFUs2kacE1eAfFVFTBMDsPR1BAy3NMpE7jZuTXfLL3ippnRRBuoJ6BcNykWCJHJ6e6Y";
        let key = XKey::from_base_58(&xpriv_string);
        let key1 = key.get_child(1);
        assert_eq!(
            key1.to_base_58(),
            "xprv46fNiru8i8kJH4CvjEZwp4d21pG9UidG9CEKHkt8Uio2D86kK5aNUa8A9nyP2MPPsLdUpfEHNnWbAKUyqNkVL9odLx8TuHWnB8iadD6ojtbnmAyQ7vkZLBMPq8jL1yCGC6MJKxyR2Axfr9rGUM8bJKaSpMwyW66NCYJiUBin1TKLv1"
        );
    }

    #[test]
    pub fn test_child_xpub() {
        let xpriv_string = "xpub5qaJDytXEfWWEb5zBzW8YBZ5ZbmBrV2z7DRtcR2qqqRM3qnDUC43XZANq9YPurzuDjjJ1xkfhsskDiaidX7z9Df5Rrtige1rcWHzTvkZGEYqUoqWREvUQshd4FRcgKTHsEFyjLTtFUL9hGVA8cYERqYQxUhcFS1Ts1a1KnPZj4g1u1";
        let key = XKey::from_base_58(&xpriv_string);
        let key1 = key.get_child(1);
        assert_eq!(
            key1.to_base_58(),
            "xpub5sWCuLLm5quygBuBFvNqbAdb8d53ohDETTVDsqM4heZ96mFctNbfQn2qE6E2soPm3ayrqKveGLF1y4JvxFhttmAxSfRUEs89AndWx4XpE3Y9zs9L2DuUtwFrqCYj7Y97aRtdaVcuHgXYnfzqR7UuJRYy6oDLPrfBEutm25Ex1ojn4p"
        );
    }
}
