use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    extended_point::{eddsa_like_decode, TwistedExtendedPoint},
    scalar::{decode_long, sub, Scalar},
};

use crate::errors::LibgoldilockErrors;

pub fn clamp(pk: &mut [u8]) {
    pk[0] &= 0xfc;
    pk[56] = 0;
    pk[55] |= 0x80;
}

pub fn sha3(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

pub fn hash_with_dom(input: &mut Vec<u8>, output: &mut [u8]) {
    let mut sig = b"SigEd448".to_vec();
    sig.push(0);
    sig.push(0);
    sig.append(input);
    let mut hasher = Shake256::default();
    hasher.update(&sig);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

// pub fn dsa_sign(sym: &[u8]) {}

pub fn dsa_verify(pubkey: &[u8], sig: &[u8], message: &[u8]) -> Result<bool, LibgoldilockErrors> {
    let p: TwistedExtendedPoint;
    match eddsa_like_decode(pubkey) {
        Ok(point) => p = point,
        Err(err) => match err {
            LibgoldilockErrors::InvalidLengthError => {
                return Err(LibgoldilockErrors::InvalidPubkeyLengthError);
            }
            LibgoldilockErrors::DecodeError => {
                return Err(LibgoldilockErrors::DecodePubkeyError);
            }
            _ => {
                panic!("Unexpected error type");
            }
        },
    }
    let scalar_zero: Scalar = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let scalar_four: Scalar = [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut p2 = p.clone();
    p2 = p2.point_scalar_mul(&scalar_four);
    let mut sig1: [u8; 57] = [0; 57];
    let mut sig2: [u8; 57] = [0; 57];

    // for i in 0..57 {
    //     sig1[i] = sig[i];
    //     sig2[i] = sig[i + 57];
    // }

    sig1[..57].copy_from_slice(&sig[..57]);
    sig2[..57].copy_from_slice(&sig[57..(57 + 57)]);

    let mut r_point: TwistedExtendedPoint;
    match eddsa_like_decode(&sig1) {
        Ok(point) => r_point = point,
        Err(err) => match err {
            LibgoldilockErrors::InvalidLengthError => {
                return Err(LibgoldilockErrors::InvalidSignatureLengthError);
            }
            LibgoldilockErrors::DecodeError => {
                return Err(LibgoldilockErrors::DecodeSignatureError);
            }
            _ => {
                panic!("Unexpected error type");
            }
        },
    }

    r_point = r_point.point_scalar_mul(&scalar_four);

    let mut challenge: [u8; 114] = [0; 114];
    let mut h = sig1.to_vec();
    h.append(&mut p.eddsa_like_encode().to_vec());
    h.append(&mut message.to_vec());
    hash_with_dom(&mut h, &mut challenge);

    let mut challenge_scalar = decode_long(&challenge);
    challenge_scalar = sub(&scalar_zero, &challenge_scalar);

    let responce_scalar = decode_long(&sig2);

    let pk = p2.point_double_scalamul_non_secret(&responce_scalar, &challenge_scalar);

    Ok(r_point.mod_equal(&pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_dsa_verify() {
        let sig: [u8; 114] = [
            211, 255, 226, 207, 254, 186, 132, 246, 49, 201, 228, 244, 82, 199, 242, 112, 35, 180,
            142, 103, 159, 48, 173, 159, 67, 180, 239, 4, 131, 103, 14, 37, 132, 46, 253, 214, 162,
            10, 215, 79, 44, 8, 53, 30, 55, 133, 119, 99, 192, 225, 183, 135, 167, 160, 44, 92, 0,
            112, 130, 99, 178, 6, 171, 133, 46, 134, 86, 118, 179, 184, 173, 44, 134, 121, 76, 210,
            131, 27, 84, 6, 76, 218, 57, 226, 112, 58, 76, 23, 42, 29, 235, 240, 81, 224, 26, 233,
            129, 197, 138, 87, 119, 49, 18, 127, 43, 251, 122, 170, 63, 146, 66, 87, 36, 0,
        ];
        let public: [u8; 57] = [
            195, 193, 156, 26, 17, 153, 66, 251, 226, 152, 245, 223, 117, 101, 207, 48, 3, 101, 6,
            3, 98, 172, 67, 111, 92, 180, 137, 58, 219, 242, 33, 124, 171, 95, 19, 77, 117, 240,
            95, 215, 148, 192, 172, 159, 209, 0, 41, 180, 226, 130, 237, 201, 179, 228, 32, 120,
            128,
        ];
        let fox = b"The quick brown fox jumps over the lazy dog";
        let result = dsa_verify(&public, &sig, fox);
        assert_eq!(result.unwrap(), true);
    }
}
