use crate::constants32::{
    self, Dword, Sdword, Word, MONTGOMERY_FACTOR, SCALAR_BYTES, SCALAR_LIMBS, SCALAR_R2,
    SCALAR_SER_BYTES, SCALAR_WORDS, WORD_BITS,
};

const SCALAR_Q: [Word; SCALAR_WORDS] = constants32::SCALAR_Q;

pub type Scalar = [Word; SCALAR_WORDS];

pub fn create_zero_scalar() -> Scalar {
    let r: Scalar = [0; SCALAR_WORDS];
    r
}

#[allow(dead_code)]
pub fn copy(a: &Scalar) -> Scalar {
    let mut r = create_zero_scalar();
    r[..SCALAR_WORDS].copy_from_slice(&a[..SCALAR_WORDS]);
    r
}

#[allow(dead_code)]
pub fn set(w: Word) -> Scalar {
    let mut r = create_zero_scalar();
    r[0] = w;
    r
}

pub fn sub_extra(minuend: &Scalar, subtrahend: &Scalar, carry: &Word) -> Scalar {
    let mut r = create_zero_scalar();
    let mut chain: Sdword = 0;
    for i in 0..SCALAR_WORDS {
        chain += minuend[i] as Sdword - subtrahend[i] as Sdword;
        r[i] = chain as Word;
        chain >>= WORD_BITS;
    }

    let borrow = chain + *carry as Sdword;
    chain = 0;

    for i in 0..SCALAR_WORDS {
        chain += r[i] as Sdword + ((SCALAR_Q[i] as Sdword) & borrow);
        r[i] = chain as Word;
        chain >>= WORD_BITS;
    }
    r
}

pub fn add(a: &Scalar, b: &Scalar) -> Scalar {
    let mut r = create_zero_scalar();
    let mut chain: Dword = 0;
    for i in 0..SCALAR_WORDS {
        chain += a[i] as Dword + b[i] as Dword;
        r[i] = chain as Word;
        chain >>= WORD_BITS;
    }
    r = sub_extra(&r, &SCALAR_Q, &(chain as Word));
    r
}

pub fn sub(a: &Scalar, b: &Scalar) -> Scalar {
    let no_extra = 0 as Word;
    sub_extra(a, b, &no_extra)
}

pub fn halve(mut s: Scalar) -> Scalar {
    let mask: Word = u32::wrapping_sub(0, s[0] & 1);
    let mut chain: Dword = 0;

    for i in 0..SCALAR_WORDS {
        chain = u64::wrapping_add(
            chain,
            u64::wrapping_add(s[i] as Dword, (SCALAR_Q[i] & mask) as Dword),
        );
        s[i] = chain as Word;
        chain >>= WORD_BITS;
    }
    for i in 0..(SCALAR_WORDS - 1) {
        s[i] = (s[i] >> 1) | (s[i + 1] << (WORD_BITS - 1));
    }

    s[SCALAR_WORDS - 1] = (s[SCALAR_WORDS - 1] >> 1) | ((chain << (WORD_BITS - 1)) as Word);

    s
}

#[allow(clippy::needless_range_loop)]
pub fn montgomery_multiply(x: &Scalar, y: &Scalar) -> Scalar {
    let mut out = create_zero_scalar();
    let mut carry = 0 as Word;
    for i in 0..SCALAR_WORDS {
        let mut chain = 0 as Dword;
        for j in 0..SCALAR_WORDS {
            chain = u64::wrapping_add(
                u64::wrapping_add(
                    u64::wrapping_mul(x[i] as Dword, y[j] as Dword),
                    out[j] as Dword,
                ),
                chain,
            );
            out[j] = chain as Word;
            chain >>= WORD_BITS;
        }

        let saved = chain as Word;
        let multiplicand = u32::wrapping_mul(out[0], MONTGOMERY_FACTOR);
        chain = 0 as Dword;

        for j in 0..SCALAR_WORDS {
            chain = u64::wrapping_add(
                u64::wrapping_add(
                    u64::wrapping_mul(multiplicand as Dword, SCALAR_Q[j] as Dword),
                    out[j] as Dword,
                ),
                chain,
            );
            if j > 0 {
                out[j - 1] = chain as Word;
            }
            chain >>= WORD_BITS;
        }
        chain = u64::wrapping_add(u64::wrapping_add(saved as Dword, carry as Dword), chain);
        out[SCALAR_WORDS - 1] = chain as Word;
        carry = (chain >> WORD_BITS) as Word;
    }
    out = sub_extra(&out, &SCALAR_Q, &carry);

    out
}

pub fn mul(x: &Scalar, y: &Scalar) -> Scalar {
    let s = montgomery_multiply(x, y);
    montgomery_multiply(&s, &SCALAR_R2)
}

#[allow(clippy::needless_range_loop)]
pub fn decode_short(b: &[u8], size: usize) -> Scalar {
    let mut s = create_zero_scalar();
    let mut k: usize = 0;
    for i in 0..SCALAR_LIMBS {
        let mut out: Word = 0;
        for j in 0..4_usize {
            if k >= size {
                break;
            }
            out |= (b[k] as Word) << (8 * j);
            k += 1;
        }
        s[i] = out;
    }
    s
}

#[allow(unused_variables)]
pub fn decode(b: &[u8]) -> Scalar {
    let s = decode_short(b, SCALAR_BYTES);

    let mut accum = 0 as Sdword;
    for i in 0..SCALAR_LIMBS {
        accum += s[i] as Sdword - SCALAR_Q[i] as Sdword;
        accum >>= WORD_BITS;
    }

    mul(
        &s,
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    )
}

#[allow(clippy::needless_range_loop)]
pub fn encode(s: &Scalar) -> [u8; 57] {
    let word_bytes = WORD_BITS / 8;
    let mut dst: [u8; 57] = [0; 57];
    let mut k: usize = 0;
    for i in 0..SCALAR_LIMBS {
        for j in 0..word_bytes {
            let b = s[i] >> (8 * j);
            dst[k] = b as u8;
            k += 1;
        }
    }

    dst
}

pub fn decode_long(b: &[u8]) -> Scalar {
    let mut y = create_zero_scalar();
    let b_len = b.len();
    let mut size = b_len - (b_len % SCALAR_SER_BYTES);
    if b_len == 0 {
        return y;
    }
    if size == b_len {
        size -= SCALAR_SER_BYTES;
    }
    let mut res = decode_short(&b[size..b_len], b_len - size);
    if b_len == SCALAR_SER_BYTES {
        res = mul(
            &res,
            &[
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        return res;
    }

    while size > 0 {
        size -= SCALAR_SER_BYTES;
        res = montgomery_multiply(&res, &SCALAR_R2);
        y = decode(&b[size..b_len]);
        res = add(&res, &y);
    }

    res
}

#[cfg(test)]
mod tests {
    use crate::{
        constants32::{SCALAR_R2, SCALAR_ZERO},
        scalar::{add, copy, halve, mul, set, sub, Scalar, SCALAR_Q},
    };

    use super::{decode_long, encode, montgomery_multiply};

    #[test]
    fn test_scalar_copy() {
        let result: Scalar = [
            0xffb823a3, 0xc96a3c35, 0x7f8ed27d, 0x087b8fb9, 0x1d9ac30a, 0x74d65764, 0xc0be082e,
            0xa8cb0ae8, 0xa8fa552b, 0x2aae8688, 0x2c3dc273, 0x47cf8cac, 0x3b089f07, 0x1e63e807,
        ];
        let b = copy(&result);
        assert_eq!(result, b);
    }

    #[test]
    fn test_scalar_set() {
        let a = set(0xee);
        let mut result = [0; 14];
        result[0] = 0xee;
        assert_eq!(result, a);
    }

    #[test]
    fn test_add_scalars() {
        let a: Scalar = [
            0x529eec33, 0x721cf5b5, 0xc8e9c2ab, 0x7a4cf635, 0x44a725bf, 0xeec492d9, 0x0cd77058,
            0x00000002, 0, 0, 0, 0, 0, 0,
        ];
        let b: Scalar = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp: Scalar = [
            0x529eec34, 0x721cf5b5, 0xc8e9c2ab, 0x7a4cf635, 0x44a725bf, 0xeec492d9, 0x0cd77058,
            0x00000002, 0, 0, 0, 0, 0, 0,
        ];
        let mut result: Scalar = add(&a, &b);
        assert_eq!(result, exp);

        result = add(&b, &SCALAR_Q);
        assert_eq!(result, b);
    }

    #[test]
    fn test_sub_scalars() {
        let mut a: Scalar = [0; 14];
        a[0] = 2;
        let mut b: Scalar = [0; 14];
        b[0] = 1;
        let mut result = sub(&a, &b);
        assert_eq!(result, b);
        result = sub(&b, &a);
        assert_eq!(result, sub(&SCALAR_Q, &b));
    }

    #[test]
    fn test_scalar_halve() {
        let mut a: Scalar = [0; 14];
        a[0] = 0x0c;
        let mut b: Scalar = [0; 14];
        b[0] = 0x06;
        assert_eq!(b, halve(a));
    }

    #[test]
    fn test_montgomery_multiply() {
        let mut a: Scalar = [
            0xd013f18b, 0xa03bc31f, 0xa5586c00, 0x5269ccea, 0x80becb3f, 0x38058556, 0x736c3c5b,
            0x07909887, 0x87190ede, 0x2aae8688, 0x2c3dc273, 0x47cf8cac, 0x3b089f07, 0x1e63e807,
        ];
        let b: Scalar = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut exp: Scalar = [
            0xf19fb32f, 0x62bc6ae6, 0xed626086, 0x0e2d81d7, 0x7a83d54b, 0x38e73799, 0x485ad3d6,
            0x45399c9e, 0x824b12d9, 0x5ae842c9, 0x5ca5b606, 0x3c0978b3, 0x893b4262, 0x22c93812,
        ];
        let mut out = montgomery_multiply(&a, &b);
        assert_eq!(exp, out);

        out = montgomery_multiply(&out, &SCALAR_R2);
        assert_eq!(a, out);

        a = [
            0xd013f18b, 0xa03bc31f, 0xa5586c00, 0x5269ccea, 0x80becb3f, 0x38058556, 0x736c3c5b,
            0x07909887, 0x87190ede, 0x2aae8688, 0x2c3dc273, 0x47cf8cac, 0x3b089f07, 0x1e63e807,
        ];
        out = montgomery_multiply(&a, &SCALAR_ZERO);
        assert_eq!(out, SCALAR_ZERO);

        let x: Scalar = [
            0xffb823a3, 0xc96a3c35, 0x7f8ed27d, 0x087b8fb9, 0x1d9ac30a, 0x74d65764, 0xc0be082e,
            0xa8cb0ae8, 0xa8fa552b, 0x2aae8688, 0x2c3dc273, 0x47cf8cac, 0x3b089f07, 0x1e63e807,
        ];
        let y: Scalar = [
            0xd8bedc42, 0x686eb329, 0xe416b899, 0x17aa6d9b, 0x1e30b38b, 0x188c6b1a, 0xd099595b,
            0xbc343bcb, 0x1adaa0e7, 0x24e8d499, 0x8e59b308, 0x0a92de2d, 0xcae1cb68, 0x16c5450a,
        ];
        exp = [
            0x14aec10b, 0x426d3399, 0x3f79af9e, 0xb1f67159, 0x6aa5e214, 0x33819c2b, 0x19c30a89,
            0x480bdc8b, 0x7b3e1c0f, 0x5e01dfc8, 0x9414037f, 0x345954ce, 0x611e7191, 0x19381160,
        ];
        out = montgomery_multiply(&x, &y);
        assert_eq!(out, exp);
    }

    #[test]
    fn test_scalar_multiply() {
        let a: Scalar = [
            0xffb823a3, 0xc96a3c35, 0x7f8ed27d, 0x087b8fb9, 0x1d9ac30a, 0x74d65764, 0xc0be082e,
            0xa8cb0ae8, 0xa8fa552b, 0x2aae8688, 0x2c3dc273, 0x47cf8cac, 0x3b089f07, 0x1e63e807,
        ];
        let b: Scalar = [
            0xd8bedc42, 0x686eb329, 0xe416b899, 0x17aa6d9b, 0x1e30b38b, 0x188c6b1a, 0xd099595b,
            0xbc343bcb, 0x1adaa0e7, 0x24e8d499, 0x8e59b308, 0x0a92de2d, 0xcae1cb68, 0x16c5450a,
        ];
        let exp: Scalar = [
            0xa18d010a, 0x1f5b3197, 0x994c9c2b, 0x6abd26f5, 0x08a3a0e4, 0x36a14920, 0x74e9335f,
            0x07bcd931, 0xf2d89c1e, 0xb9036ff6, 0x203d424b, 0xfccd61b3, 0x4ca389ed, 0x31e055c1,
        ];
        assert_eq!(mul(&a, &b), exp);
    }

    #[test]
    fn test_scalar_decode() {
        let mut b: &[u8] = &[];
        let mut x = decode_long(&b);
        assert_eq!(x, SCALAR_ZERO);

        b = &[
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ];
        let mut exp: Scalar = [
            0x2a1c3d02, 0x12f970e8, 0x41d97de7, 0x6a547b38, 0xdaa8c88e, 0x9f299b75, 0x01075c7b,
            0x3b874ad9, 0xe1c0b914, 0xc8bd0b68, 0xc3f34776, 0x2f2d9082, 0x4b75d258, 0x34a8bc39,
        ];
        x = decode_long(&b);
        assert_eq!(x, exp);

        b = &[
            0xf0, 0xe4, 0x4d, 0xd4, 0x98, 0xf3, 0xad, 0x30, 0x83, 0xe1, 0xf5, 0xfc, 0xc1, 0x44,
            0xed, 0x1f, 0xf5, 0xfb, 0x62, 0x5b, 0xa6, 0x21, 0x41, 0xa8, 0xde, 0x2a, 0x90, 0x23,
            0x13, 0xb3, 0x1a, 0xd1, 0x41, 0x13, 0x42, 0x94, 0xdb, 0x9b, 0x0d, 0x84, 0xec, 0x43,
            0x7a, 0x51, 0x5a, 0x9b, 0x85, 0xbd, 0xa1, 0xb1, 0x5e, 0xac, 0xeb, 0xe4, 0xa3, 0xb2,
            0x0,
        ];
        exp = [
            0x7d9d5b0a, 0xe9bc6e73, 0xe16ac2d8, 0xdd13bfdc, 0xfdb68ed4, 0x1fa36b12, 0x29fbe30b,
            0xd11ab314, 0x94421341, 0x840d9bdb, 0x517a43ec, 0xbd859b5a, 0xac5eb1a1, 0x32a3e4eb,
        ];
        x = decode_long(&b);
        assert_eq!(x, exp);
    }

    #[test]
    fn test_scalar_decode_very_long() {
        let inp: [u8; 114] = [
            0x71, 0xd6, 0x2, 0xd2, 0x13, 0x94, 0x49, 0x29, 0x75, 0x18, 0xd1, 0xc7, 0x4e, 0x2d,
            0x45, 0x44, 0x60, 0x2a, 0xbb, 0xbb, 0x68, 0xfd, 0xb9, 0x15, 0xd8, 0xea, 0xd9, 0xc,
            0xa6, 0xd9, 0x66, 0x72, 0x37, 0x8b, 0x2, 0xb2, 0xf1, 0xa2, 0x62, 0x9a, 0xba, 0x56, 0xf,
            0xc9, 0xb3, 0x9d, 0x8d, 0x3d, 0xda, 0x2f, 0xe6, 0x78, 0x62, 0x27, 0x61, 0x6e, 0xe9,
            0x36, 0x13, 0xc, 0xcc, 0x34, 0x5, 0x67, 0xd0, 0xcf, 0x76, 0x90, 0xc5, 0xf6, 0x91, 0xd7,
            0x78, 0x82, 0x44, 0xeb, 0xbe, 0xb3, 0x75, 0xc4, 0x61, 0xee, 0x5e, 0x9c, 0x41, 0xee,
            0xdc, 0xa7, 0xbf, 0x3f, 0x91, 0x36, 0x81, 0x30, 0x12, 0x67, 0x19, 0x68, 0x2b, 0x1c,
            0x73, 0x28, 0x38, 0x5c, 0x16, 0x72, 0xe6, 0xb9, 0x2, 0x6e, 0xe4, 0xcf, 0x56, 0x19,
        ];
        let exp: [u8; 57] = [
            0x12, 0x00, 0x7a, 0x28, 0x40, 0x53, 0x6a, 0xd4, 0x89, 0xe0, 0x0c, 0x6e, 0xc7, 0xfa,
            0x7a, 0xc6, 0xe1, 0x77, 0x8e, 0x8e, 0x34, 0xb8, 0xd3, 0x5c, 0x61, 0x84, 0x73, 0xcc,
            0xb4, 0xf6, 0x38, 0x9c, 0x6c, 0xf3, 0x2f, 0xa4, 0xca, 0x70, 0xfe, 0x2d, 0x4f, 0xca,
            0x08, 0x2b, 0x38, 0xfd, 0xc7, 0x31, 0xf3, 0x1b, 0x6d, 0x87, 0xf5, 0x15, 0xe6, 0x1b, 0,
        ];
        let sc = decode_long(&inp);
        let res = encode(&sc);
        assert_eq!(res, exp);
    }
}
