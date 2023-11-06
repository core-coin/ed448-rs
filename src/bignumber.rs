use crate::{
    constants32::{
        BigNumber, Dword, Sdword, Serialized, Word, BIG_ZERO, FIELD_BYTES, LMASK, MODULUS, N_LIMBS,
        RADIX, RADIX_MASK, WORD_BITS,
    },
    karatsuba_32::karatsuba_mul,
    karatsuba_square_32::karatsuba_square,
};

pub fn create_zero_bignumber() -> BigNumber {
    [0; N_LIMBS]
}

pub fn low_bit(x: &BigNumber) -> Word {
    let mut y = *x;
    y = strong_reduce(y);

    u32::wrapping_sub(0, y[0] & 1)
}

pub fn is_zero_mask(n: Word) -> Word {
    let mut nn = n as Dword;
    nn = u64::wrapping_sub(nn, 1);
    (nn >> WORD_BITS) as Word
}

fn bias(mut n: BigNumber, b: Word) -> BigNumber {
    let co1 = RADIX_MASK * b;
    let co2 = co1 - b;

    n[0] = u32::wrapping_add(n[0], co1);
    n[1] = u32::wrapping_add(n[1], co1);
    n[2] = u32::wrapping_add(n[2], co1);
    n[3] = u32::wrapping_add(n[3], co1);
    n[4] = u32::wrapping_add(n[4], co1);
    n[5] = u32::wrapping_add(n[5], co1);
    n[6] = u32::wrapping_add(n[6], co1);
    n[7] = u32::wrapping_add(n[7], co1);

    n[8] = u32::wrapping_add(n[8], co2);
    n[9] = u32::wrapping_add(n[9], co1);
    n[10] = u32::wrapping_add(n[10], co1);
    n[11] = u32::wrapping_add(n[11], co1);
    n[12] = u32::wrapping_add(n[12], co1);
    n[13] = u32::wrapping_add(n[13], co1);
    n[14] = u32::wrapping_add(n[14], co1);
    n[15] = u32::wrapping_add(n[15], co1);
    n
}

#[allow(dead_code)]
pub fn constant_time_greater_or_equal_p(n: &BigNumber) -> Word {
    let mut ge = LMASK;

    n.iter().take(4).for_each(|x| ge &= x);

    ge = (ge & (n[4] + 1)) | is_zero_mask((n[4] ^ RADIX_MASK) as Word);

    n.iter().take(8).skip(5).for_each(|x| ge &= x);

    !is_zero_mask((ge ^ RADIX_MASK) as Word)
}

pub fn invert(x: &BigNumber) -> BigNumber {
    let mut t1 = square(x);
    let t2 = isr(&t1);
    t1 = square(&t2);

    mul(&t1, x)
}

#[allow(unused_assignments)]
pub fn isr(x: &BigNumber) -> BigNumber {
    let mut l1 = square(x);
    let mut l2 = mul(x, &l1);
    l1 = square(&l2);
    l2 = mul(x, &l1);
    l1 = square_n(&l2, 3);
    let mut l0 = mul(&l2, &l1);
    l1 = square_n(&l0, 3);
    l0 = mul(&l2, &l1);
    l2 = square_n(&l0, 9);
    l1 = mul(&l0, &l2);
    l0 = square(&l1);
    l2 = mul(x, &l0);
    l0 = square_n(&l2, 18);
    l2 = mul(&l1, &l0);
    l0 = square_n(&l2, 37);
    l1 = mul(&l2, &l0);
    l0 = square_n(&l1, 37);
    l1 = mul(&l2, &l0);
    l0 = square_n(&l1, 111);
    l2 = mul(&l1, &l0);
    l0 = square(&l2);
    l1 = mul(x, &l0);
    l0 = square_n(&l1, 223);
    l1 = mul(&l2, &l0);
    l2 = square(&l1);
    l0 = mul(&l2, x);
    // Is this correctly returning l1?

    l1
}

pub fn square_n(x: &BigNumber, mut y: usize) -> BigNumber {
    let mut n;
    if y & 1 != 0 {
        n = square(x);
        y -= 1;
    } else {
        n = square(&square(x));
        y -= 2;
    }
    while y > 0 {
        n = square(&square(&n));
        y -= 2;
    }
    n
}

pub fn neg_raw(x: &BigNumber) -> BigNumber {
    let mut n = create_zero_bignumber();
    n[0] = u32::wrapping_sub(0, x[0]);
    n[1] = u32::wrapping_sub(0, x[1]);
    n[2] = u32::wrapping_sub(0, x[2]);
    n[3] = u32::wrapping_sub(0, x[3]);
    n[4] = u32::wrapping_sub(0, x[4]);
    n[5] = u32::wrapping_sub(0, x[5]);
    n[6] = u32::wrapping_sub(0, x[6]);
    n[7] = u32::wrapping_sub(0, x[7]);
    n[8] = u32::wrapping_sub(0, x[8]);
    n[9] = u32::wrapping_sub(0, x[9]);
    n[10] = u32::wrapping_sub(0, x[10]);
    n[11] = u32::wrapping_sub(0, x[11]);
    n[12] = u32::wrapping_sub(0, x[12]);
    n[13] = u32::wrapping_sub(0, x[13]);
    n[14] = u32::wrapping_sub(0, x[14]);
    n[15] = u32::wrapping_sub(0, x[15]);

    n
}

pub fn neg(x: &BigNumber) -> BigNumber {
    weak_reduce(bias(neg_raw(x), 2))
}

pub fn constant_time_select(x: &BigNumber, y: &BigNumber, first: &Word) -> BigNumber {
    let mut a = *x;
    let mut b = *y;
    conditional_swap(&mut b, &mut a, first);
    b
}

pub fn conditional_negate(n: &BigNumber, negate: &Word) -> BigNumber {
    constant_time_select(&neg(n), n, negate)
}

pub fn add_raw(x: &BigNumber, y: &BigNumber) -> BigNumber {
    let mut n = create_zero_bignumber();
    n[0] = u32::wrapping_add(x[0], y[0]);
    n[1] = u32::wrapping_add(x[1], y[1]);
    n[2] = u32::wrapping_add(x[2], y[2]);
    n[3] = u32::wrapping_add(x[3], y[3]);
    n[4] = u32::wrapping_add(x[4], y[4]);
    n[5] = u32::wrapping_add(x[5], y[5]);
    n[6] = u32::wrapping_add(x[6], y[6]);
    n[7] = u32::wrapping_add(x[7], y[7]);
    n[8] = u32::wrapping_add(x[8], y[8]);
    n[9] = u32::wrapping_add(x[9], y[9]);
    n[10] = u32::wrapping_add(x[10], y[10]);
    n[11] = u32::wrapping_add(x[11], y[11]);
    n[12] = u32::wrapping_add(x[12], y[12]);
    n[13] = u32::wrapping_add(x[13], y[13]);
    n[14] = u32::wrapping_add(x[14], y[14]);
    n[15] = u32::wrapping_add(x[15], y[15]);

    n
}

pub fn add(x: &BigNumber, y: &BigNumber) -> BigNumber {
    weak_reduce(add_raw(x, y))
}

pub fn sub_raw(x: &BigNumber, y: &BigNumber) -> BigNumber {
    let mut n = create_zero_bignumber();
    n[0] = u32::wrapping_sub(x[0], y[0]);
    n[1] = u32::wrapping_sub(x[1], y[1]);
    n[2] = u32::wrapping_sub(x[2], y[2]);
    n[3] = u32::wrapping_sub(x[3], y[3]);
    n[4] = u32::wrapping_sub(x[4], y[4]);
    n[5] = u32::wrapping_sub(x[5], y[5]);
    n[6] = u32::wrapping_sub(x[6], y[6]);
    n[7] = u32::wrapping_sub(x[7], y[7]);
    n[8] = u32::wrapping_sub(x[8], y[8]);
    n[9] = u32::wrapping_sub(x[9], y[9]);
    n[10] = u32::wrapping_sub(x[10], y[10]);
    n[11] = u32::wrapping_sub(x[11], y[11]);
    n[12] = u32::wrapping_sub(x[12], y[12]);
    n[13] = u32::wrapping_sub(x[13], y[13]);
    n[14] = u32::wrapping_sub(x[14], y[14]);
    n[15] = u32::wrapping_sub(x[15], y[15]);

    n
}

pub fn sub(x: &BigNumber, y: &BigNumber) -> BigNumber {
    weak_reduce(bias(sub_raw(x, y), 2))
}

pub fn sub_x_bias(x: &BigNumber, y: &BigNumber, amt: &Word) -> BigNumber {
    weak_reduce(bias(sub_raw(x, y), *amt))
}

pub fn square(x: &BigNumber) -> BigNumber {
    karatsuba_square(x)
}

pub fn mul(x: &BigNumber, y: &BigNumber) -> BigNumber {
    karatsuba_mul(x, y)
}

pub fn mul_w(x: &BigNumber, w: &Dword) -> BigNumber {
    let mut n = create_zero_bignumber();

    let whi = (w >> RADIX) as Word;
    let wlo = (w & (RADIX_MASK as Dword)) as Word;

    let mut accum0: Dword;
    let mut accum8: Dword;

    accum0 = u64::wrapping_mul(wlo as Dword, x[0] as Dword);
    accum8 = u64::wrapping_mul(wlo as Dword, x[8] as Dword);
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[15] as Dword));
    accum8 = u64::wrapping_add(
        accum8,
        u64::wrapping_mul(whi as Dword, (x[15] + x[7]) as Dword),
    );

    n[0] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[8] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 1
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[1] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[9] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[0] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[8] as Dword));

    n[1] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[9] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 2
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[2] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[10] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[1] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[9] as Dword));

    n[2] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[10] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 3
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[3] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[11] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[2] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[10] as Dword));

    n[3] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[11] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 4
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[4] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[12] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[3] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[11] as Dword));

    n[4] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[12] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 5
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[5] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[13] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[4] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[12] as Dword));

    n[5] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[13] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 6
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[6] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[14] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[5] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[13] as Dword));

    n[6] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[14] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // 7
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(wlo as Dword, x[7] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(wlo as Dword, x[15] as Dword));
    accum0 = u64::wrapping_add(accum0, u64::wrapping_mul(whi as Dword, x[6] as Dword));
    accum8 = u64::wrapping_add(accum8, u64::wrapping_mul(whi as Dword, x[14] as Dword));

    n[7] = (accum0 & (RADIX_MASK as Dword)) as Word;
    accum0 >>= RADIX;

    n[15] = (accum8 & (RADIX_MASK as Dword)) as Word;
    accum8 >>= RADIX;

    // finish
    accum0 += accum8 + (n[8] as Dword);
    n[8] = (accum0 & (RADIX_MASK as Dword)) as Word;
    n[9] = u32::wrapping_add(n[9], (accum0 >> RADIX) as Word);

    accum8 += n[0] as Dword;
    n[0] = (accum8 & (RADIX_MASK as Dword)) as Word;
    n[1] = u32::wrapping_add(n[1], (accum8 >> RADIX) as Word);

    n
}

pub fn mul_with_signed_curve_constant(x: &BigNumber, c: &Sdword) -> BigNumber {
    if c > &0 {
        return mul_w(x, &(*c as Dword));
    };
    let r = mul_w(x, &((-*c) as Dword));
    sub(&BIG_ZERO, &r)
}

pub fn conditional_swap(n: &mut BigNumber, x: &mut BigNumber, swap: &Word) {
    for i in 0..N_LIMBS {
        let s = (x[i] ^ n[i]) & swap;
        x[i] ^= s;
        n[i] ^= s;
    }
}

pub fn weak_reduce(mut n: BigNumber) -> BigNumber {
    let tmp = ((n[N_LIMBS - 1] as Dword) >> RADIX) as Word;
    n[N_LIMBS / 2] = u32::wrapping_add(n[N_LIMBS / 2], tmp);

    n[15] = u32::wrapping_add(n[15] & RADIX_MASK, n[14] >> RADIX);
    n[14] = u32::wrapping_add(n[14] & RADIX_MASK, n[13] >> RADIX);
    n[13] = u32::wrapping_add(n[13] & RADIX_MASK, n[12] >> RADIX);
    n[12] = u32::wrapping_add(n[12] & RADIX_MASK, n[11] >> RADIX);
    n[11] = u32::wrapping_add(n[11] & RADIX_MASK, n[10] >> RADIX);
    n[10] = u32::wrapping_add(n[10] & RADIX_MASK, n[9] >> RADIX);
    n[9] = u32::wrapping_add(n[9] & RADIX_MASK, n[8] >> RADIX);
    n[8] = u32::wrapping_add(n[8] & RADIX_MASK, n[7] >> RADIX);
    n[7] = u32::wrapping_add(n[7] & RADIX_MASK, n[6] >> RADIX);
    n[6] = u32::wrapping_add(n[6] & RADIX_MASK, n[5] >> RADIX);
    n[5] = u32::wrapping_add(n[5] & RADIX_MASK, n[4] >> RADIX);
    n[4] = u32::wrapping_add(n[4] & RADIX_MASK, n[3] >> RADIX);
    n[3] = u32::wrapping_add(n[3] & RADIX_MASK, n[2] >> RADIX);
    n[2] = u32::wrapping_add(n[2] & RADIX_MASK, n[1] >> RADIX);
    n[1] = u32::wrapping_add(n[1] & RADIX_MASK, n[0] >> RADIX);
    n[0] = u32::wrapping_add(n[0] & RADIX_MASK, tmp);

    n
}

pub fn strong_reduce(mut n: BigNumber) -> BigNumber {
    n = weak_reduce(n);

    let mut scarry = 0 as Sdword;
    scarry += i64::wrapping_sub(n[0] as Sdword, 0xfffffff);
    n[0] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[1] as Sdword, 0xfffffff);
    n[1] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[2] as Sdword, 0xfffffff);
    n[2] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[3] as Sdword, 0xfffffff);
    n[3] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[4] as Sdword, 0xfffffff);
    n[4] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[5] as Sdword, 0xfffffff);
    n[5] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[6] as Sdword, 0xfffffff);
    n[6] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[7] as Sdword, 0xfffffff);
    n[7] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[8] as Sdword, 0xffffffe);
    n[8] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[9] as Sdword, 0xfffffff);
    n[9] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[10] as Sdword, 0xfffffff);
    n[10] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[11] as Sdword, 0xfffffff);
    n[11] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[12] as Sdword, 0xfffffff);
    n[12] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[13] as Sdword, 0xfffffff);
    n[13] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[14] as Sdword, 0xfffffff);
    n[14] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    scarry += i64::wrapping_sub(n[15] as Sdword, 0xfffffff);
    n[15] = scarry as Word & RADIX_MASK;
    scarry >>= 28;

    let scarry_mask = (scarry as Word) & (RADIX_MASK as Word);
    let mut carry = 0 as Dword;
    let m = scarry_mask as Dword;

    carry += u64::wrapping_add(n[0] as Dword, m);
    n[0] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[1] as Dword, m);
    n[1] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[2] as Dword, m);
    n[2] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[3] as Dword, m);
    n[3] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[4] as Dword, m);
    n[4] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[5] as Dword, m);
    n[5] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[6] as Dword, m);
    n[6] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[7] as Dword, m);
    n[7] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[8] as Dword, m & (0xfffffffffffffffe as Dword));
    n[8] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[9] as Dword, m);
    n[9] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[10] as Dword, m);
    n[10] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[11] as Dword, m);
    n[11] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[12] as Dword, m);
    n[12] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[13] as Dword, m);
    n[13] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[14] as Dword, m);
    n[14] = carry as Word & RADIX_MASK;
    carry >>= 28;

    carry += u64::wrapping_add(n[15] as Dword, m);
    n[15] = carry as Word & RADIX_MASK;

    n
}

pub fn decaf_equal(n: &BigNumber, x: &BigNumber) -> Word {
    let mut y = sub(n, x);
    y = strong_reduce(y);
    let mut ret: Word = 0;

    ret |= y[0];
    ret |= y[1];
    ret |= y[2];
    ret |= y[3];
    ret |= y[4];
    ret |= y[5];
    ret |= y[6];
    ret |= y[7];
    ret |= y[8];
    ret |= y[9];
    ret |= y[10];
    ret |= y[11];
    ret |= y[12];
    ret |= y[13];
    ret |= y[14];

    is_zero_mask(ret)
}

pub fn decaf_const_time_select(x: &BigNumber, y: &BigNumber, neg: &Word) -> BigNumber {
    let mut n = create_zero_bignumber();
    n[0] = (x[0] & !neg) | (y[0] & neg);
    n[1] = (x[1] & !neg) | (y[1] & neg);
    n[2] = (x[2] & !neg) | (y[2] & neg);
    n[3] = (x[3] & !neg) | (y[3] & neg);
    n[4] = (x[4] & !neg) | (y[4] & neg);
    n[5] = (x[5] & !neg) | (y[5] & neg);
    n[6] = (x[6] & !neg) | (y[6] & neg);
    n[7] = (x[7] & !neg) | (y[7] & neg);
    n[8] = (x[8] & !neg) | (y[8] & neg);
    n[9] = (x[9] & !neg) | (y[9] & neg);
    n[10] = (x[10] & !neg) | (y[10] & neg);
    n[11] = (x[11] & !neg) | (y[11] & neg);
    n[12] = (x[12] & !neg) | (y[12] & neg);
    n[13] = (x[13] & !neg) | (y[13] & neg);
    n[14] = (x[14] & !neg) | (y[14] & neg);
    n[15] = (x[15] & !neg) | (y[15] & neg);

    n
}

pub fn decaf_cond_negate(n: &BigNumber, neg: &Word) -> BigNumber {
    let m = sub(&BIG_ZERO, n);
    decaf_const_time_select(n, &m, neg)
}

#[allow(dead_code)]
pub fn deserialize_return_mask(inp: Serialized) -> (BigNumber, Word) {
    let mut n = create_zero_bignumber();

    for i in 0..8 {
        let mut out = 0 as Dword;
        for j in 0..7 {
            out |= (inp[7 * i + j] as Dword) << (8 * j)
        }

        n[2 * i] = (out as Word) & RADIX_MASK;
        n[2 * i + 1] = (out >> 28) as Word;
    }

    (n, constant_time_greater_or_equal_p(&n))
}

#[allow(dead_code)]
pub fn deserialize(inp: Serialized) -> (BigNumber, bool) {
    let (n, mask) = deserialize_return_mask(inp);
    let ok = mask == LMASK;
    (n, ok)
}

#[allow(dead_code)]
pub fn must_deserialize(inp: Serialized) -> BigNumber {
    let (n, ok) = deserialize(inp);
    if !ok {
        panic!("Failed to deserialize");
    }

    n
}

pub fn dsa_like_deserialize(input: &[u8], mask: usize) -> (BigNumber, Word) {
    let mut n = create_zero_bignumber();

    let mut fill: usize = 0;
    let mut j: usize = 0;
    let mut buffer = 0 as Dword;
    let mut scarry = 0 as Sdword;

    for i in 0..N_LIMBS {
        while fill < RADIX && j < FIELD_BYTES {
            let mut sj = input[j] as usize;
            if j == FIELD_BYTES - 1 {
                sj &= !mask;
            }
            buffer |= (sj as Dword) << fill;
            fill += 8;
            j += 1;
        }

        if i >= N_LIMBS - 1 {
            n[i] = buffer as Word;
        } else {
            n[i] = (buffer & (((1 << RADIX) as Dword) - 1)) as Word;
        }
        fill -= RADIX;
        buffer >>= RADIX;
        // TODO CHECK SCARRY NOT SURE IF CORRECT
        scarry = ((u32::wrapping_sub(u32::wrapping_add(scarry as Word, n[i]), MODULUS[i]) >> 8) * 4)
            as Sdword;
    }

    (
        n,
        (is_zero_mask(buffer as Word) & !is_zero_mask(scarry as Word)),
    )
}

pub fn dsa_like_serialize(n: &BigNumber) -> [u8; FIELD_BYTES] {
    let mut x = *n;
    let mut res: [u8; FIELD_BYTES] = [0; FIELD_BYTES];
    x = strong_reduce(x);
    let mut j: usize = 0;
    let mut fill: usize = 0;
    let mut buffer = 0 as Dword;
    res.iter_mut().take(FIELD_BYTES).for_each(|item| {
        if fill < 8 && j < N_LIMBS {
            buffer |= (x[j] as Dword) << fill;
            fill += RADIX;
            j += 1;
        }
        *item = buffer as u8;
        fill -= 8;
        buffer >>= 8;
    });
    res
}

#[cfg(test)]
mod tests {
    use crate::constants32::{BIG_ONE, BIG_ZERO, DECAF_TRUE, EDWARDS_D, FIELD_BYTES};

    use super::*;

    #[test]
    pub fn test_deserialize() {
        let mut ser = [0; FIELD_BYTES];
        ser[0] = 1;
        let (mut n, mut ok) = deserialize(ser);

        assert_eq!(n, BIG_ONE);
        assert_eq!(ok, true);

        ser = [
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ];

        (n, ok) = deserialize(ser);
        assert_eq!(ok, true);
        assert_eq!(
            n,
            [
                0x57481f5, 0x72337ad, 0xf0d3c36, 0x3daacf9, 0xf1e8bc1, 0xbf897ef, 0x5637876,
                0x7dd1806, 0xb874ad8, 0xc0b9143, 0xd0b68e1, 0x4776c8b, 0x082c3f3, 0x582f2d9,
                0x94b75d2, 0x74a8bc3
            ]
        );

        ser = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        (n, ok) = deserialize(ser);
        assert_eq!(ok, false);
        assert_eq!(
            n,
            [
                0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
                0xfffffff, 0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
                0xfffffff, 0xfffffff
            ]
        );
    }

    #[test]
    pub fn test_strong_reduce() {
        let (mut n, _) = deserialize([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);

        n = strong_reduce(n);
        assert_eq!(n, BIG_ZERO);

        n = must_deserialize([
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ]);

        n = strong_reduce(n);

        assert_eq!(
            n,
            must_deserialize([
                0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
                0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
                0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
                0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74
            ])
        );
    }

    #[test]
    fn test_subtraction() {
        let mut x = must_deserialize([
            0xda, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut y = must_deserialize([
            0x83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut exp = must_deserialize([
            0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(strong_reduce(sub(&x, &y)), exp);

        x = must_deserialize([
            0, 0, 0, 0xf1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        y = must_deserialize([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        exp = must_deserialize([
            0xff, 0xff, 0xff, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ]);
        assert_eq!(strong_reduce(sub(&x, &y)), exp);
    }

    #[test]
    fn test_addition() {
        let mut x = must_deserialize([
            0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut y = must_deserialize([
            0x83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut exp = must_deserialize([
            0xda, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(add(&x, &y), exp);

        exp = must_deserialize([
            0, 0, 0, 0xf1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        y = must_deserialize([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        x = must_deserialize([
            0xff, 0xff, 0xff, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ]);
        assert_eq!(add(&x, &y), exp);
    }

    #[test]
    fn test_sub_x_bias() {
        let x = must_deserialize([
            0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let y = must_deserialize([
            0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let exp = [
            0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
            0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
        ];
        assert_eq!(exp, sub_x_bias(&x, &y, &(2 as Word)));
    }

    #[test]
    fn test_conditional_swap() {
        let x = must_deserialize([
            0xe6, 0xf5, 0xb8, 0xae, 0x49, 0xce, 0xf7, 0x79, 0xe5, 0x77, 0xdc, 0x29, 0x82, 0x4e,
            0xff, 0x45, 0x3f, 0x1c, 0x41, 0x06, 0x03, 0x00, 0x88, 0x11, 0x5e, 0xa4, 0x9b, 0x4e,
            0xe8, 0x4a, 0x7b, 0x7c, 0xdf, 0xe0, 0x6e, 0x0d, 0x62, 0x2f, 0xc5, 0x5c, 0x7c, 0x55,
            0x9a, 0xb1, 0xf6, 0xc3, 0xea, 0x32, 0x57, 0xc0, 0x79, 0x79, 0x80, 0x90, 0x26, 0xde,
        ]);
        let y = must_deserialize([
            0x19, 0x0a, 0x47, 0x51, 0xb6, 0x31, 0x08, 0x86, 0x1a, 0x88, 0x23, 0xd6, 0x7d, 0xb1,
            0x00, 0xba, 0xc0, 0xe3, 0xbe, 0xf9, 0xfc, 0xff, 0x77, 0xee, 0xa1, 0x5b, 0x64, 0xb0,
            0x17, 0xb5, 0x84, 0x83, 0x20, 0x1f, 0x91, 0xf2, 0x9d, 0xd0, 0x3a, 0xa3, 0x83, 0xaa,
            0x65, 0x4e, 0x09, 0x3c, 0x15, 0xcd, 0xa8, 0x3f, 0x86, 0x86, 0x7f, 0x6f, 0xd9, 0x21,
        ]);
        let mut a = must_deserialize([
            0xe6, 0xf5, 0xb8, 0xae, 0x49, 0xce, 0xf7, 0x79, 0xe5, 0x77, 0xdc, 0x29, 0x82, 0x4e,
            0xff, 0x45, 0x3f, 0x1c, 0x41, 0x06, 0x03, 0x00, 0x88, 0x11, 0x5e, 0xa4, 0x9b, 0x4e,
            0xe8, 0x4a, 0x7b, 0x7c, 0xdf, 0xe0, 0x6e, 0x0d, 0x62, 0x2f, 0xc5, 0x5c, 0x7c, 0x55,
            0x9a, 0xb1, 0xf6, 0xc3, 0xea, 0x32, 0x57, 0xc0, 0x79, 0x79, 0x80, 0x90, 0x26, 0xde,
        ]);
        let mut b = must_deserialize([
            0x19, 0x0a, 0x47, 0x51, 0xb6, 0x31, 0x08, 0x86, 0x1a, 0x88, 0x23, 0xd6, 0x7d, 0xb1,
            0x00, 0xba, 0xc0, 0xe3, 0xbe, 0xf9, 0xfc, 0xff, 0x77, 0xee, 0xa1, 0x5b, 0x64, 0xb0,
            0x17, 0xb5, 0x84, 0x83, 0x20, 0x1f, 0x91, 0xf2, 0x9d, 0xd0, 0x3a, 0xa3, 0x83, 0xaa,
            0x65, 0x4e, 0x09, 0x3c, 0x15, 0xcd, 0xa8, 0x3f, 0x86, 0x86, 0x7f, 0x6f, 0xd9, 0x21,
        ]);
        conditional_swap(&mut a, &mut b, &LMASK);
        assert_eq!(a, y);
        assert_eq!(b, x);
        conditional_swap(&mut a, &mut b, &0);
        assert_eq!(a, y);
        assert_eq!(b, x);
    }

    #[test]
    fn test_isr() {
        let mut x = must_deserialize([
            0x9f, 0x93, 0xed, 0x0a, 0x84, 0xde, 0xf0, 0xc7, 0xa0, 0x4b, 0x3f, 0x03, 0x70, 0xc1,
            0x96, 0x3d, 0xc6, 0x94, 0x2d, 0x93, 0xf3, 0xaa, 0x7e, 0x14, 0x96, 0xfa, 0xec, 0x9c,
            0x70, 0xd0, 0x59, 0x3c, 0x5c, 0x06, 0x5f, 0x24, 0x33, 0xf7, 0xad, 0x26, 0x6a, 0x3a,
            0x45, 0x98, 0x60, 0xf4, 0xaf, 0x4f, 0x1b, 0xff, 0x92, 0x26, 0xea, 0xa0, 0x7e, 0x29,
        ]);
        x = isr(&x);
        let exp: BigNumber = [
            29773570, 137982333, 1945968, 118417199, 265338750, 53110653, 197553960, 191470666,
            233741762, 151481942, 109183904, 77807714, 38252586, 5438964, 61033406, 4204497,
        ];
        assert_eq!(x, exp);
    }

    #[test]
    fn test_square_n() {
        let gx = must_deserialize([
            0x9f, 0x93, 0xed, 0x0a, 0x84, 0xde, 0xf0, 0xc7, 0xa0, 0x4b, 0x3f, 0x03, 0x70, 0xc1,
            0x96, 0x3d, 0xc6, 0x94, 0x2d, 0x93, 0xf3, 0xaa, 0x7e, 0x14, 0x96, 0xfa, 0xec, 0x9c,
            0x70, 0xd0, 0x59, 0x3c, 0x5c, 0x06, 0x5f, 0x24, 0x33, 0xf7, 0xad, 0x26, 0x6a, 0x3a,
            0x45, 0x98, 0x60, 0xf4, 0xaf, 0x4f, 0x1b, 0xff, 0x92, 0x26, 0xea, 0xa0, 0x7e, 0x29,
        ]);
        let mut exp = gx.clone();
        for _i in 0..5 {
            exp = square(&exp);
        }
        let n = square_n(&gx, 5);
        assert_eq!(exp, n);

        exp = gx.clone();
        for _i in 0..6 {
            exp = square(&exp);
        }
        let n = square_n(&gx, 6);
        assert_eq!(exp, n);
    }

    #[test]
    fn test_dsa_like_deserialize() {
        let ser: [u8; 57] = [
            0xa5, 0xd9, 0xce, 0xa4, 0x06, 0x89, 0xa4, 0x13, 0x94, 0xf0, 0x69, 0x32, 0xfe, 0xe0,
            0xdb, 0x11, 0x7b, 0xe0, 0x75, 0x78, 0x68, 0x2c, 0x48, 0x44, 0x70, 0x3b, 0xe9, 0xc6,
            0x64, 0xde, 0x6c, 0xe0, 0xd6, 0xa5, 0xa3, 0x4e, 0xe7, 0x38, 0xd9, 0xb3, 0x0c, 0x93,
            0x75, 0x75, 0x8d, 0xe8, 0x50, 0xde, 0x06, 0x2c, 0xb9, 0x75, 0x50, 0x7d, 0x24, 0x85,
            0x0,
        ];
        let exp: BigNumber = [
            0x04ced9a5, 0x0a48906a, 0x09f09413, 0x0e0fe326, 0x007b11db, 0x0687875e, 0x0044482c,
            0x0c6e93b7, 0x006cde64, 0x0a3a5d6e, 0x0938e74e, 0x0930cb3d, 0x088d7575, 0x006de50e,
            0x0075b92c, 0x085247d5,
        ];
        let (dst, ok) = dsa_like_deserialize(&ser, 0);
        assert_eq!(dst, exp);
        assert_eq!(ok, DECAF_TRUE);
    }

    #[test]
    fn test_mul_w() {
        let (x, _) = deserialize([
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ]);
        let w: Dword = 0x2;
        let w1: BigNumber = [
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let r1 = mul(&x, &w1);
        let r2 = mul_w(&x, &w);
        assert_eq!(r1, r2);
    }
    #[test]
    fn test_mul_with_signed_curve_constant() {
        let x = must_deserialize([
            0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0,
        ]);
        let exp: BigNumber = [
            0xffecead, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
            0xffffffe, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff, 0xfffffff,
        ];
        let res = mul_with_signed_curve_constant(&x, &EDWARDS_D);
        assert_eq!(exp, res);
    }

    #[test]
    fn test_decaf_cond_negate() {
        let x = [
            9447134, 201824152, 65679959, 162209644, 89947221, 14033660, 215998574, 243574711,
            245668686, 557333, 205587971, 267670513, 204046926, 127817597, 239718135, 242178954,
        ];
        let exp = [
            258988321, 66611303, 202755496, 106225811, 178488234, 254401795, 52436881, 24860744,
            22766768, 267878122, 62847484, 764942, 64388529, 140617858, 28717320, 26256501,
        ];
        assert_eq!(exp, decaf_cond_negate(&x, &LMASK));
    }
}
