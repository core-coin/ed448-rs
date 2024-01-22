use rand::RngCore;

use crate::errors::LibgoldilockErrors;
use crate::{
    eddsa::{clamp, dsa_verify, hash_with_dom, sha3},
    extended_point::{precomputed_scalar_mul, TwistedExtendedPoint},
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
    dsa_verify(pubkey, sig, message)
}

pub fn ed448_verify_with_error(
    pubkey: &[u8],
    sig: &[u8],
    message: &[u8],
) -> Result<(), LibgoldilockErrors> {
    let is_ok = dsa_verify(pubkey, sig, message)?;
    if !is_ok {
        return Err(LibgoldilockErrors::InvalidSignatureError);
    }
    Ok(())
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
        let message = hex_to_message_hash("f092a4af1f2103fe7be067df44370097c444f3bf877783ba56f21cf70ba365a3");
        let result = ed448_verify(&pk, &sig, &message);
        assert_eq!(result, Err(LibgoldilockErrors::DecodePubkeyError));
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
