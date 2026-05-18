use rand::RngCore;

use crate::errors::LibgoldilockErrors;
use crate::{
    eddsa::{clamp, dsa_verify, hash_with_dom, sha3},
    extended_point::{
        add_extended_to_extended, eddsa_like_decode, precomputed_scalar_mul, TwistedExtendedPoint,
    },
    scalar::{self, decode_long, encode, halve},
};

pub type PrivateKey = [u8; 57];
pub type PublicKey = [u8; 57];

pub fn hex_to_message_hash(hexx: &str) -> [u8; 32] {
    let mut p: [u8; 32] = [0; 32];
    hex::decode_to_slice(hexx, &mut p).expect("Decoding failed");
    p
}

pub fn hex_to_private_key(hexx: &str) -> PrivateKey {
    let mut p: PrivateKey = [0; 57];
    hex::decode_to_slice(hexx, &mut p).expect("Decoding failed");
    p
}

pub fn hex_to_signature(hexx: &str) -> [u8; 114] {
    let mut s: [u8; 114] = [0; 114];
    hex::decode_to_slice(hexx, &mut s).expect("Decoding failed");
    s
}

pub fn point_by_secret(p: &PrivateKey) -> TwistedExtendedPoint {
    let mut digest = *p;
    clamp(&mut digest);

    let mut r = decode_long(&digest);
    r = halve(r);
    r = halve(r);
    precomputed_scalar_mul(r)
}

pub fn private_to_secret(pk: &PrivateKey) -> PrivateKey {
    let mut sk: PrivateKey = [0; 57];
    sha3(pk, &mut sk);
    sk[56] |= 0x80;
    sk
}

pub fn secret_to_public(sk: &PrivateKey) -> PublicKey {
    let h = point_by_secret(sk);
    let p: PublicKey = h.eddsa_like_encode();

    p
}

pub fn private_to_public(pk: &PrivateKey) -> PublicKey {
    secret_to_public(&private_to_secret(pk))
}

pub fn sign_by_private(pk: &PrivateKey, message: &[u8]) -> [u8; 114] {
    let mut secret: [u8; 114] = [0; 114];
    sha3(pk, &mut secret);
    clamp(&mut secret);
    let mut sk: [u8; 57] = [0; 57];
    sk.clone_from_slice(&secret[0..57]);
    let sec = decode_long(&sk);
    let mut seed: [u8; 57] = [0; 57];
    seed.clone_from_slice(&secret[57..114]);
    let point = point_by_secret(&sk);

    let mut nonce: [u8; 114] = [0; 114];
    let mut v1: Vec<u8> = seed.to_vec();
    v1.append(&mut message.to_vec());
    hash_with_dom(&mut v1, &mut nonce);
    let nonce_scalar = decode_long(&nonce);
    let mut nonce_scalar2 = nonce_scalar;
    nonce_scalar2 = halve(nonce_scalar2);
    nonce_scalar2 = halve(nonce_scalar2);
    let nonce_point = precomputed_scalar_mul(nonce_scalar2).eddsa_like_encode();

    let mut challenge: [u8; 114] = [0; 114];
    let mut h = nonce_point.to_vec();
    h.append(&mut point.eddsa_like_encode().to_vec());
    h.append(&mut message.to_vec());
    hash_with_dom(&mut h, &mut challenge);

    let mut challenge_scalar = decode_long(&challenge);
    challenge_scalar = scalar::mul(&challenge_scalar, &sec);
    challenge_scalar = scalar::add(&challenge_scalar, &nonce_scalar);

    let mut result: [u8; 114] = [0; 114];
    result[0..57].copy_from_slice(&nonce_point);
    result[57..114].copy_from_slice(&encode(&challenge_scalar));

    result
}

pub fn sign_with_secret_and_nonce(
    secret: &PrivateKey,
    n: &PrivateKey,
    message: &[u8],
) -> [u8; 114] {
    let mut s1 = *secret;
    clamp(&mut s1);
    let sec = decode_long(&s1);

    let pub_point = point_by_secret(secret);

    let mut nonce: [u8; 114] = [0; 114];
    let mut v1: Vec<u8> = n.to_vec();
    v1.append(&mut message.to_vec());
    hash_with_dom(&mut v1, &mut nonce);
    let nonce_scalar = decode_long(&nonce);
    let mut nonce_scalar2 = nonce_scalar;
    nonce_scalar2 = halve(nonce_scalar2);
    nonce_scalar2 = halve(nonce_scalar2);
    let nonce_point = precomputed_scalar_mul(nonce_scalar2).eddsa_like_encode();

    let mut challenge: [u8; 114] = [0; 114];
    let mut h = nonce_point.to_vec();
    h.append(&mut pub_point.eddsa_like_encode().to_vec());
    h.append(&mut message.to_vec());
    hash_with_dom(&mut h, &mut challenge);

    let mut challenge_scalar = decode_long(&challenge);
    challenge_scalar = scalar::mul(&challenge_scalar, &sec);
    challenge_scalar = scalar::add(&challenge_scalar, &nonce_scalar);

    let mut result: [u8; 114] = [0; 114];
    result[0..57].copy_from_slice(&nonce_point);
    result[57..114].copy_from_slice(&encode(&challenge_scalar));

    result
}

pub fn ed448_derive_public(pk: &PrivateKey) -> PublicKey {
    if pk[57 - 1] & 0x80 == 0x00 {
        private_to_public(pk)
    } else {
        secret_to_public(pk)
    }
}

pub fn ed448_sign(pk: &PrivateKey, message: &[u8]) -> [u8; 114] {
    if pk[57 - 1] & 0x80 == 0x00 {
        sign_by_private(pk, message)
    } else {
        let mut digest = *pk;
        clamp(&mut digest);

        sign_with_secret_and_nonce(&digest, &digest, message)
    }
}

pub fn ed448_verify(pubkey: &[u8], sig: &[u8], message: &[u8]) -> Result<bool, LibgoldilockErrors> {
    let zero_public_key: [u8; 57] = [0; 57];
    let zero_signature: [u8; 114] = [0; 114];
    if pubkey == &zero_public_key || sig == &zero_signature {
        return Err(LibgoldilockErrors::InvalidSignatureError);
    }
    dsa_verify(pubkey, sig, message)
}

pub fn ed448_verify_with_error(
    pubkey: &[u8],
    sig: &[u8],
    message: &[u8],
) -> Result<(), LibgoldilockErrors> {
    let zero_public_key: [u8; 57] = [0; 57];
    let zero_signature: [u8; 114] = [0; 114];
    if pubkey == &zero_public_key || sig == &zero_signature {
        return Err(LibgoldilockErrors::InvalidSignatureError);
    }

    let is_ok = dsa_verify(pubkey, sig, message)?;
    if !is_ok {
        return Err(LibgoldilockErrors::InvalidSignatureError);
    }
    Ok(())
}

pub fn add_two_public(pub1: &PublicKey, pub2: &PublicKey) -> Result<PublicKey, LibgoldilockErrors> {
    let p1 = eddsa_like_decode(pub1)?;
    let p2 = eddsa_like_decode(pub2)?;

    Ok(add_extended_to_extended(&p1, &p2).eddsa_like_encode())
}

pub fn ed448_generate_key() -> PrivateKey {
    let mut random_key: PrivateKey = [0; 57];
    rand::thread_rng().fill_bytes(&mut random_key);
    random_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_decode_hex() {
        let pk = hex_to_private_key("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56");
        let exp: PrivateKey = [
            168, 234, 33, 44, 194, 74, 224, 253, 2, 154, 151, 182, 75, 229, 64, 136, 90, 240, 225,
            183, 220, 159, 175, 74, 89, 23, 66, 133, 12, 67, 119, 248, 87, 174, 154, 143, 135, 223,
            29, 233, 142, 57, 122, 88, 103, 221, 111, 32, 33, 30, 243, 242, 52, 174, 113, 188, 86,
        ];
        assert_eq!(pk, exp);
    }

    #[test]
    pub fn test_private_to_secret() {
        let pk = hex_to_private_key("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56");
        let exp = hex_to_private_key("1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594");
        let sk = private_to_secret(&pk);
        assert_eq!(sk, exp);
    }

    #[test]
    pub fn test_secret_to_public() {
        let pk = hex_to_private_key("1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594");
        let pubk = secret_to_public(&pk);
        let exp: PublicKey = hex_to_private_key("b615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880");
        assert_eq!(pubk, exp);
    }

    #[test]
    pub fn test_private_to_public() {
        let pk = hex_to_private_key("a8ea212cc24ae0fd029a97b64be540885af0e1b7dc9faf4a591742850c4377f857ae9a8f87df1de98e397a5867dd6f20211ef3f234ae71bc56");
        let pubk = private_to_public(&pk);
        let exp: PublicKey = hex_to_private_key("b615e57dd4d15c3ed1323725c0ba8b1d7f6e740d08e0e29c6d3ff564c896c0c3dd28a9bb5065e06725c8f9e3f7c2c6bbad4900b7447ecf9880");
        assert_eq!(pubk, exp);
    }

    #[test]
    pub fn test_sign_with_private() {
        let pk = hex_to_private_key("64c2754ee8f55f285d1c6efac34345c78da28df5c31d9ae3748417e0754903004eca31389e978df148e3941de8d4c3585b6dd3669903f00bb5");
        let fox = b"The quick brown fox jumps over the lazy dog";
        let sig = sign_by_private(&pk, fox);
        let sig2 = hex_to_signature("d3ffe2cffeba84f631c9e4f452c7f27023b48e679f30ad9f43b4ef0483670e25842efdd6a20ad74f2c08351e37857763c0e1b787a7a02c5c00708263b206ab852e865676b3b8ad2c86794cd2831b54064cda39e2703a4c172a1debf051e01ae981c58a577731127f2bfb7aaa3f9242572400");
        assert_eq!(sig, sig2);
    }

    #[test]
    pub fn test_sign_with_secret_and_nonce() {
        let pk = hex_to_private_key("26ad14d91ef8f1e5bbf5a1a7e44a9532e4854f1e1346761ee9b4ed1ed103e5e05c87fd9ecd788bc879a7433a7115255b7aad667fe84ee35c28");
        let n = hex_to_private_key("66dd9754284a1b7d77c1c43bfdfe38a116bd143e7c901b8e8e4561a7ee0a401dd5120fa2b77e2a6bda3a68d5a47e34fd29cf14ce3489067602");
        let fox = b"The quick brown fox jumps over the lazy dog";
        let sig = sign_with_secret_and_nonce(&pk, &n, fox);
        let sig2 = hex_to_signature("71e4ae51aa4d1f59f10efaaca743ca557079c2de1d298375d80eac8c53d29567add49f6296206f6c0d56ad3cd3f34b3644b1b01361900bea803aae2018aea2db72a2c5557a207ba17b8316335817b4a9474def73b3ea0ddaaae593e76596fbeac45c8ef04df3bb23dc809d2b7db49dbf0a00");
        assert_eq!(sig, sig2);
    }

    // #[test]
    // pub fn test_secret_to_public_benchmarks() {
    //     let pk = hex_to_private_key("1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594");
    //     let before = SystemTime::now();
    //     for i in 0..10000 {
    //         let pubk = secret_to_public(&pk);
    //     }
    //     let duration = before.elapsed().unwrap();
    //     println!("{:?}", duration);
    // }

    // #[test]
    // pub fn test_overall() {
    //     let pk = hex_to_private_key("64c2754ee8f55f285d1c6efac34345c78da28df5c31d9ae3748417e0754903004eca31389e978df148e3941de8d4c3585b6dd3669903f00bb5");
    //     let fox = b"The quick brown fox jumps over the lazy dog";
    //     let sig = ed448_sign(&pk, fox);
    //     let public = private_to_public(&pk);
    //     let mut v = ed448_verify(&public, &sig, fox);
    //     assert_eq!(v, true);

    //     let pk1 = hex_to_private_key("64c2754ee8f55f285d1c6efac34345c78da28df5c31d9ae3748417e0754903004eca31389e978df148e3941de8d4c3585b6dd3669903f00bb6");
    //     let public1 = ed448_derive_public(&pk1);
    //     v = ed448_verify(&public1, &sig, fox);
    //     assert_eq!(v, false);

    // }

    #[test]
    pub fn test_ed448_derive_public() {
        let mut pk = hex_to_private_key("582f73eb3d951ef93a8c392c7b113ad85c0f60a744c95c47370d4d593593edc0d745eb24fa2130f51fd5b1e6b2363a5405bf1e074ecbf4382d");
        let mut pubk = ed448_derive_public(&pk);
        let mut exp: PublicKey = hex_to_private_key("4e6ef3aa2a74ce85c9c75de379c72abbce30601db4f66af1535d00190fa5de83af3831fa32e37c59e14a25788e56140896fb59b494e4fdca80");
        assert_eq!(pubk, exp);

        pk = hex_to_private_key("59fc82f514f3fc8d02d987e52a03cdcae81a257bed6ec9b668bf6acd8fe9e7d27cbcc4d8f463d917642d30e7ca44c3521370f78790b3b561dd");
        pubk = ed448_derive_public(&pk);
        exp = hex_to_private_key("3cba3b2560c2779170ce5947f55bf73b93a1dd51d99b0b483ed0cfb5a9bb8409830c0f96068c799dbc6a28ca6bc1aad95d0387c36a731d7800");
        assert_eq!(pubk, exp);
    }

    #[test]
    pub fn test_ed448_sign() {
        let mut pk = hex_to_private_key("e959068474bc720bf3a94c7a524750f0d4fe68a4828137e58d48303af1fa929a6c50f87d0cab27fc557aa1a3190cfad0abbca2a2e5d7da272d");
        let fox = b"The quick brown fox jumps over the lazy dog";
        let mut sig = ed448_sign(&pk, fox);
        let mut sig2 = hex_to_signature("92a7e08f86b25f288eb0308f3fb780950ab77c333d5d1b91b6de40a199fc028fe66a001dc09341905a58f8c3d4a959ee5d416735f59d91640095dd83e70b6bc05fa6a26b32c00be454bfb87285417554183c2da64bbbad77b746bd86299fd4188578bc9aa321a8291c5d2281029ca24e2d00");
        assert_eq!(sig, sig2);

        pk = hex_to_private_key("1edc2069350104b5594c602f7967c4b1580f2a757fc9a2745f621868cd333c245ec3c775d730d3c01a2e18f3e5d0b5e767ed3ec77e69732781");
        sig = ed448_sign(&pk, fox);
        sig2 = hex_to_signature("789dd9e1a4471c30cfef1da68076542e6918676424593936dbeb282f5929dcfa3437aef85fd890999ea7a1b16a2c8c3a8cf330c58768789b006b183034ec43acab783039d53fe46f6c39ab29f988a43371d07fe7746a2fd45c660f2a8c441446b8f1cdbfc0787e4cfe69280e5cd7b92d0400");
        assert_eq!(sig, sig2);
    }

    #[test]
    pub fn test_canonical_private_key_vectors() {
        let vectors = [
            (
                "incrementing",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
                "0411d38f9076da316fb9addcfe25f7c4d9403d125f3ef899409bed928bb9a30aeb9769b3b47ceba0d14ed5d7563ec01147fd18ab67cca295a8",
                "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800",
            ),
            (
                "all-01",
                "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
                "24c7392b799ff6e0086e4fd66c58c99fb4447771d01625ed5e9cd6cae05ffa038eab7b739c1d2ff034b474b62a1fe40c3f81841c1e807f1ceb",
                "e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580",
            ),
            (
                "all-02",
                "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
                "4e8214ed3f124f0f4a713b2e57686adb349c259cd39c4d0eef22b119eec5db36b80d7ca0f7f1104b36f9f3f70054719ab546fee241a2c7fbb2",
                "b52fd5b2cb34d6f944ab81d765fa026b63fd8448b4890d025cba17308a312ae4f31a012dc08c891e9a7c3d29dbad1aaf964e6c74073249f300",
            ),
        ];

        for (name, private, secret, public) in vectors {
            let pk = hex_to_private_key(private);
            assert_eq!(pk[56] & 0x80, 0, "{name} marker bit must be clear");
            assert_eq!(private_to_secret(&pk), hex_to_private_key(secret), "{name}");
            assert_eq!(
                secret_to_public(&hex_to_private_key(secret)),
                hex_to_private_key(public),
                "{name}"
            );
            assert_eq!(
                ed448_derive_public(&pk),
                hex_to_private_key(public),
                "{name}"
            );
        }
    }

    #[test]
    pub fn test_canonical_sign_verify_vectors() {
        let vectors: [(&str, &str, &str, &[u8], &str); 3] = [
            (
                "empty-message",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
                "18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800",
                b"",
                "cb682b115cf0f0b0cf2a068acba2d0495714f2a50832739af364191c611f6983890ee133a4bf75ed2d09adc5d70f6d256b0806f3224b35d7802748b7cf55f5e9583df9f8c85db809f4877191c99ed0670ad62f54d63d7d35fddfd85efbad63554ff3ce9b847607b2f79181020880f13c1b00",
            ),
            (
                "zero-byte-message",
                "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
                "e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580",
                &[0],
                "a94e33bb28aa3b07ac36178ebe75315b7d24f9d7cab4954b190d7369a3bd4f263510cd16e5bb939e3bbd6d0561b715c18b2c2ae4bf093a0500b2690980ddcdafaeb2e14663bd1e281c3125ef8dcaa46e8af6c2515d4e42b995c639388eb464977711e1725144ab6c4eb7215142cabb3f0c00",
            ),
            (
                "text-message",
                "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
                "b52fd5b2cb34d6f944ab81d765fa026b63fd8448b4890d025cba17308a312ae4f31a012dc08c891e9a7c3d29dbad1aaf964e6c74073249f300",
                b"Core Ed448 compatibility test message",
                "57c1488556a9e7e780d7630203d446f655b5f742036feb2db204ee6ffa642f2c1fa112e4bd47a289d7fa95e0df5cc8ceba45ac7ac1e251bd80e5dd228fd81a95bc1ffdb8b7936c5a69cec124a07a1ed5f40bba9b8b74576154a846a73d4a282e9ae2f8d5c15044af7aa8a2c2d38028d72c00",
            ),
        ];

        for (name, private, public, message, signature) in vectors {
            let pk = hex_to_private_key(private);
            let pubkey = hex_to_private_key(public);
            let want_sig = hex_to_signature(signature);
            let got_sig = ed448_sign(&pk, message);
            assert_eq!(got_sig, want_sig, "{name}");
            assert_eq!(
                ed448_verify(&pubkey, &got_sig, message).unwrap(),
                true,
                "{name}"
            );
        }
    }

    #[test]
    pub fn test_long_message_sign_verify_vectors() {
        let vectors = [
            (
                "64-byte-message",
                "030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
                "18e2f925aef56fc05910474593ee84c932bc7ea4d352a3416f72d115e60eb58cd862f73ac50886fbaad6354a4eeb01fd9f740491fb11f59580",
                64,
                0,
                "99706c0d43655cbbdb0987520c20a2c9c98fe169d6e9ada9ed9f1167a249aff06a6c56b8147f9bda815e709cb2c2291e324042a6c1b4896b809d9dc41058be1d814bee8d55cf065a010277c96ea9a39982a95d98b7a97ade70aefb79c4b9024c16b89e5129553c11b0dc8b4894712fa73700",
            ),
            (
                "256-byte-message",
                "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
                "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
                256,
                1,
                "e0ffeebb9584f0be43ab16bdb6e75b08b48f9ec7029376afc8822494434a9f85eb023af5279f0bfa466fe15eabb062008fd5baaf2c61f5b180d86a810e3bae994d563d7872e3a7f85fc0d0ed8179c027527f2ccc5bc9a237ff0d659e4834e83151c02caaa8ae031d398a17cd1ae816210300",
            ),
            (
                "1023-byte-message",
                "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
                "f4c0eecfc7f17d960823180420fb8074d882317a39a719480d3ba6e7f565fc518a4ff54ef7dca5df5de9bb3740384c84ecac265c81398c3400",
                1023,
                2,
                "9ae36ecbaece22e2f779a1818672467d34961d6028601c5e32d90d2ee1fd14b7fecd0168aeb7862b3ea6879fde654aae4670f3dc27aede2200d6f10899deede10db29a115c988005c52462a4e8cea1ff3846e581cf915b6b011d670c18abe9a7b90dc93d20ff82d53812a7c57c9dbdc33c00",
            ),
        ];

        for (name, private, public, msg_len, msg_offset, signature) in vectors {
            let pk = hex_to_private_key(private);
            let pubkey = hex_to_private_key(public);
            let message = deterministic_message(msg_len, msg_offset);
            let want_sig = hex_to_signature(signature);
            let got_sig = ed448_sign(&pk, &message);
            assert_eq!(got_sig, want_sig, "{name}");
            assert_eq!(
                ed448_verify(&pubkey, &got_sig, &message).unwrap(),
                true,
                "{name}"
            );
        }
    }

    #[test]
    pub fn test_sign_secret_and_nonce_vectors() {
        let secret = hex_to_private_key("26ad14d91ef8f1e5bbf5a1a7e44a9532e4854f1e1346761ee9b4ed1ed103e5e05c87fd9ecd788bc879a7433a7115255b7aad667fe84ee35c28");
        let vectors: [(&str, &str, &[u8], &str); 3] = [
            (
                "empty-message",
                "66dd9754284a1b7d77c1c43bfdfe38a116bd143e7c901b8e8e4561a7ee0a401dd5120fa2b77e2a6bda3a68d5a47e34fd29cf14ce3489067602",
                b"",
                "a5fb561f2beb377e35bbf4d93b460ebeff3b55c1d64fffbcc2168c2d3998d310ed4f581499428ed46acfed19d7c8f5aa00b8fa88a7258e9c00f40ddd5e41cd33eb569d324d16babb5e840d60b6e52df10cbb2c6ea8bb3be49f39dace9cdfc7f606c2f4bfeef7bab2ab85fb787c8041302a00",
            ),
            (
                "zero-byte-message",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
                &[0],
                "23a56dc2bd6db200aded4a2ad5cea6083f29b412c5575f3c4f14d53373f14b9cc03e37a3c49bfd445cd4766f7b14c3755cb6849ac357ca8880ca1a9bb804d0bab2227a0e1e8ca798f77aa59c7f98541551f6c6b5ecf89c336272e96323094b7eb5fe20cf966f94c307aab6d303f138c82500",
            ),
            (
                "text-message",
                "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
                b"Core Ed448 compatibility test message",
                "2175036838bce81b72161107af10e67a39ea968ca6edfc0a1a074c3d14ae69bb7a446ca6b3c5a54727957f2bca8f2738cd8efd6a9645385500af3d2fcb330cb40e0d0252274d39c298e7c01e05cf46630872f133b99787c9069ee93dc30ec9d699e859c0cd20b7bf964aae6fa690d8713d00",
            ),
        ];

        for (name, nonce, message, signature) in vectors {
            let got_sig = sign_with_secret_and_nonce(&secret, &hex_to_private_key(nonce), message);
            assert_eq!(got_sig, hex_to_signature(signature), "{name}");
        }
    }

    #[test]
    pub fn test_negative_verify_vectors() {
        let pubkey = hex_to_private_key("18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800");
        let other_pubkey = hex_to_private_key("e0758a33267939a394fb5ccb202ee851cebc2e89c91ac1289e2bfcddfd9ff9fc5694b0f569d7f7e9da16e1cde9301b29f48128b3cbd1168580");
        let signature = hex_to_signature("cb682b115cf0f0b0cf2a068acba2d0495714f2a50832739af364191c611f6983890ee133a4bf75ed2d09adc5d70f6d256b0806f3224b35d7802748b7cf55f5e9583df9f8c85db809f4877191c99ed0670ad62f54d63d7d35fddfd85efbad63554ff3ce9b847607b2f79181020880f13c1b00");
        let mut mutated_r = signature;
        mutated_r[0] ^= 0x01;
        let mut mutated_s = signature;
        mutated_s[57] ^= 0x01;
        let mut invalid_r = signature;
        invalid_r[..57].fill(0xff);
        let mut non_canonical_r = signature;
        non_canonical_r[..57].copy_from_slice(&non_canonical_ed448_encoding_p());
        let zero_pubkey: PublicKey = [0; 57];
        let zero_signature = [0; 114];
        let invalid_pubkey: PublicKey = [0xff; 57];
        let non_canonical_pubkey = non_canonical_ed448_encoding_p();

        let vectors: [(&str, PublicKey, [u8; 114], &[u8]); 11] = [
            ("wrong-message", pubkey, signature, &[0]),
            ("wrong-public-key", other_pubkey, signature, b""),
            ("mutated-r", pubkey, mutated_r, b""),
            ("mutated-s", pubkey, mutated_s, b""),
            ("zero-public-key", zero_pubkey, signature, b""),
            ("zero-signature", pubkey, zero_signature, b""),
            (
                "zero-public-key-and-signature",
                zero_pubkey,
                zero_signature,
                b"",
            ),
            ("invalid-public-key", invalid_pubkey, signature, b""),
            ("invalid-r", pubkey, invalid_r, b""),
            (
                "non-canonical-public-key-y-ge-p",
                non_canonical_pubkey,
                signature,
                b"",
            ),
            ("non-canonical-r-y-ge-p", pubkey, non_canonical_r, b""),
        ];

        for (name, public, sig, message) in vectors {
            assert_ne!(ed448_verify(&public, &sig, message), Ok(true), "{name}");
        }
    }

    #[test]
    pub fn test_ed448_verify_rejects_non_canonical_r_extra_bit() {
        let public = hex_to_private_key("3d4012b96522a8d939d1d60d24c667ba76b73d0921f7b6417a6fded1aa1d6d8c53c60b9236a5939dd241e93cd51ea4a8c8d931dd9b63c13100");
        let signature = hex_to_signature("92a7e08f86b25f288eb0308f3fb780950ab77c333d5d1b91b6de40a199fc028fe66a001dc09341905a58f8c3d4a959ee5d416735f59d91640168fdb4d8ddf19127e015e2db7f3485c0652652f579a8203e37059cafd3c20b61d94d5f0c960805a93c72658dd679c0ace427f431087aa00300");
        let message = b"The quick brown fox jumps over the lazy dog";

        assert_ne!(ed448_verify(&public, &signature, message), Ok(true));
    }

    #[test]
    pub fn test_ed448_verify_identity_a_r_zero_s() {
        let mut public = [0; 57];
        public[0] = 1;
        let mut signature = [0; 114];
        signature[0] = 1;

        assert_ne!(ed448_verify(&public, &signature, b""), Ok(true));
    }

    #[test]
    pub fn test_ed448_verify_accepts_small_order_a_r_zero_s() {
        let mut public = [0; 57];
        public[56] = 0x80;
        let mut signature = [0; 114];
        signature[56] = 0x80;

        assert_eq!(ed448_verify(&public, &signature, b"").unwrap(), true);
    }

    #[test]
    pub fn test_ed448_verify_panics_on_wrong_signature_length() {
        let public = hex_to_private_key("18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800");
        let signature = hex_to_signature("cb682b115cf0f0b0cf2a068acba2d0495714f2a50832739af364191c611f6983890ee133a4bf75ed2d09adc5d70f6d256b0806f3224b35d7802748b7cf55f5e9583df9f8c85db809f4877191c99ed0670ad62f54d63d7d35fddfd85efbad63554ff3ce9b847607b2f79181020880f13c1b00");

        assert!(
            std::panic::catch_unwind(|| ed448_verify(&public, &signature[..113], b"")).is_err()
        );
        assert!(std::panic::catch_unwind(|| {
            let mut long_signature = signature.to_vec();
            long_signature.push(0);
            ed448_verify(&public, &long_signature, b"")
        })
        .is_err());
    }

    #[test]
    pub fn test_add_two_public_vectors() {
        let vectors = [
            (
                "existing-wrapper-vector",
                "5475efbfc0fa155f3fd80a8c183260eef996532fd084899e32df9cb8db9eb34410d2ea0d4f8b273fbd79c3276b50b70fea40732ad88f45de00",
                "d666091b1b3836d082d349e66521878cf7afc734329d5d132d8ebd06bebf6514aaad5794dbafed3fd6aa1c5d59d5db914e8460041ff3db6280",
                "6af04e1137833cbf82878fcdcd8310851fe582320690990a7497de63389311588d4c0d4d6fce79d07958824e54ef11fabd23b815c81e79ea80",
            ),
            (
                "three-four",
                "18e2f925aef56fc05910474593ee84c932bc7ea4d352a3416f72d115e60eb58cd862f73ac50886fbaad6354a4eeb01fd9f740491fb11f59580",
                "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
                "6e99288aed0db282ae0e8d8fe03b9dc084eb201c0d6e143def07ea02d7ada39d0ae4ecea04ec451910a4c5fb2695dd1c224b0ba507b986c180",
            ),
            (
                "four-five",
                "4e15975a78604b2d6575f2d3310ca4e4f122226189f5900f744c1ead49408bdf8247843c05ba24fbb26c9b5f81c287cbbe3d3e8a3ad0231d00",
                "f4c0eecfc7f17d960823180420fb8074d882317a39a719480d3ba6e7f565fc518a4ff54ef7dca5df5de9bb3740384c84ecac265c81398c3400",
                "1ef1b114f0a020826789550fe32e0922d367687653aa3e4a5f32363b2ed25a3bc338d9758512c6d8e7e7d53a11005bba5db96e1fa4fe9acb80",
            ),
        ];

        for (name, public1, public2, expected) in vectors {
            let public1 = hex_to_private_key(public1);
            let public2 = hex_to_private_key(public2);
            let expected = hex_to_private_key(expected);
            let got = add_two_public(&public1, &public2).unwrap();

            assert_eq!(got, expected, "{name}");
        }
    }

    #[test]
    pub fn test_add_two_public_rejects_invalid_public_key() {
        let public = hex_to_private_key("18d0a70e42a742dfb561279893385061d7b4dad8f6feed4791eaab66b2f4a4f02fc09462a8bfb1842d0bac60e8a1b3e55ba2407f33226f3800");
        let invalid_public = [0xff; 57];

        assert!(add_two_public(&public, &invalid_public).is_err());
        assert!(add_two_public(&invalid_public, &public).is_err());
    }

    #[test]
    pub fn batch_test_sign_verify() {
        let n: usize = 100;
        let fox = b"The quick brown fox jumps over the lazy dog";
        for _i in 0..n {
            let pk = ed448_generate_key();
            let sig = ed448_sign(&pk, fox);
            let true_pub = ed448_derive_public(&pk);
            let mut result = ed448_verify(&true_pub, &sig, fox);
            assert_eq!(result.unwrap(), true);
            let false_pub = ed448_derive_public(&ed448_generate_key());
            result = ed448_verify(&false_pub, &sig, fox);
            assert_eq!(result.unwrap(), false);
        }
    }

    #[test]
    pub fn test_incorrect_public_key() {
        let sig = hex_to_signature("611d178b128095022653965eb0ed3bc8bbea8e7891b5a121a102a5b29bb895770d204354dbbc67c5567186f92cdb58a601397dfe0022e0ce002c1333b6829c37c732fb909501f719df200ceaaa0e0a1533dc22e4c9c999406c071fee2858bc7c76c66d113ff1ac739564d465cd541b0d1e00");
        let pk = hex_to_private_key("3761457fcdd53dba3dea5848c43aa54fe468284319f032945a3acb9bd4cd0fa7b7c901d978e9acd9eca43fa5b3c32b648c33dcc3f3169e8081");
        let message =
            hex_to_message_hash("f092a4af1f2103fe7be067df44370097c444f3bf877783ba56f21cf70ba365a3");
        let result = ed448_verify(&pk, &sig, &message);
        assert_eq!(result, Err(LibgoldilockErrors::DecodePubkeyError));
    }

    #[test]
    pub fn test_zero_public_and_signature() {
        let sig = hex_to_signature("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let pk = hex_to_private_key("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let message =
            hex_to_message_hash("f092a4af1f2103fe7be067df44370097c444f3bf877783ba56f21cf70ba365a3");
        let result = ed448_verify(&pk, &sig, &message);
        assert_eq!(result, Err(LibgoldilockErrors::InvalidSignatureError));
    }

    fn deterministic_message(length: usize, offset: usize) -> Vec<u8> {
        (0..length).map(|i| ((i + offset) & 0xff) as u8).collect()
    }

    fn non_canonical_ed448_encoding_p() -> [u8; 57] {
        let mut encoding = [0xff; 57];
        encoding[28] = 0xfe;
        encoding[56] = 0x00;
        encoding
    }

    // #[test]
    // pub fn test_ed448_verify() {
    //     let mut sig = hex_to_signature("fe25200421dd73065668979b4cedc19ddd8536db632d4bc61a569cc07906cc9485c2b1999dcd2234d18e7393b5ec8f21802bd76b6fddb08b808be5264c2a7992474e7efa947019dedb0a0ab5405313837c2270f7b56dfe57b5ccbe6df20f5866231b1ce0df77aeb603944500d0c5e22b3000");
    //     let mut pk = hex_to_private_key("bddc6f8ef904cc39eff871720fcf794575aa285809c09602ceff06fd741e8a39b2304779778e20c9ac76bc4c5628b6f1ad03d49d3dd09b4380");
    //     let message = hex_to_message_hash("1f7d6d8c8133fb9807148f7188b797ac3d6308df12fc03d37de6ec5088c2f547");
    //     let result = ed448_verify(&pk, &sig, &message).unwrap();
    //     println!("{:?}", result);
    // }
}
