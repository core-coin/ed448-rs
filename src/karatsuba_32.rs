use crate::constants32::{BigNumber, Dword, Word, N_LIMBS, RADIX_MASK};

pub fn karatsuba_mul(a: &BigNumber, b: &BigNumber) -> BigNumber {
    let mut c = [0; N_LIMBS];

    let mut aa = [0 as Dword; 8];
    let mut bb = [0 as Dword; 8];
    for i in 0..8 {
        aa[i] = u64::wrapping_add(a[i] as Dword, a[i + 8] as Dword);
        bb[i] = u64::wrapping_add(b[i] as Dword, b[i + 8] as Dword);
    }

    let mut z2: Dword = (a[0] as Dword) * (b[0] as Dword);
    let mut z1: Dword = u64::wrapping_mul(aa[0], bb[0]);
    z1 = u64::wrapping_sub(z1, z2);
    let mut z0: Dword = (a[8] as Dword) * (b[8] as Dword);
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;

    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[1]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[2]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], bb[3]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[4], bb[4]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[3], bb[5]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[2], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[1], bb[7]));

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[9] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[10] as Dword));
    z1 = u64::wrapping_add(z1, (a[13] as Dword) * (b[11] as Dword));
    z1 = u64::wrapping_add(z1, (a[12] as Dword) * (b[12] as Dword));
    z1 = u64::wrapping_add(z1, (a[11] as Dword) * (b[13] as Dword));
    z1 = u64::wrapping_add(z1, (a[10] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[9] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[1] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[2] as Dword));
    z0 = u64::wrapping_sub(z0, (a[5] as Dword) * (b[3] as Dword));
    z0 = u64::wrapping_sub(z0, (a[4] as Dword) * (b[4] as Dword));
    z0 = u64::wrapping_sub(z0, (a[3] as Dword) * (b[5] as Dword));
    z0 = u64::wrapping_sub(z0, (a[2] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[1] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[0] = (z0 as Word) & RADIX_MASK;
    c[8] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 1
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[1] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[1]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;

    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[2]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[3]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], bb[4]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[4], bb[5]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[3], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[2], bb[7]));

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[10] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[11] as Dword));
    z1 = u64::wrapping_add(z1, (a[13] as Dword) * (b[12] as Dword));
    z1 = u64::wrapping_add(z1, (a[12] as Dword) * (b[13] as Dword));
    z1 = u64::wrapping_add(z1, (a[11] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[10] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[2] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[3] as Dword));
    z0 = u64::wrapping_sub(z0, (a[5] as Dword) * (b[4] as Dword));
    z0 = u64::wrapping_sub(z0, (a[4] as Dword) * (b[5] as Dword));
    z0 = u64::wrapping_sub(z0, (a[3] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[2] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[1] = (z0 as Word) & RADIX_MASK;
    c[9] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 2
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[2] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[2]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[3]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[4]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], bb[5]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[4], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[3], bb[7]));

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[11] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[12] as Dword));
    z1 = u64::wrapping_add(z1, (a[13] as Dword) * (b[13] as Dword));
    z1 = u64::wrapping_add(z1, (a[12] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[11] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[3] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[4] as Dword));
    z0 = u64::wrapping_sub(z0, (a[5] as Dword) * (b[5] as Dword));
    z0 = u64::wrapping_sub(z0, (a[4] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[3] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[2] = (z0 as Word) & RADIX_MASK;
    c[10] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 3
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[2] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[3] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[2]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[3]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[11] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[11] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[4]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[5]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[4], bb[7]));

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[4] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[5] as Dword));
    z0 = u64::wrapping_sub(z0, (a[5] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[4] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[12] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[13] as Dword));
    z1 = u64::wrapping_add(z1, (a[13] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[12] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    c[3] = (z0 as Word) & RADIX_MASK;
    c[11] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 4
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[4] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[2] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[3] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[4] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[2]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[3]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[4]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[12] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[11] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[11] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[12] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[5]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], bb[7]));

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[13] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[13] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[5] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[5] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[4] = (z0 as Word) & RADIX_MASK;
    c[12] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 5
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[5] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[4] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (b[2] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[3] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[4] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[5] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], bb[2]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[3]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[4]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[5]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[13] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[12] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[11] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[11] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[12] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[13] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[6]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], bb[7]));

    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[14] as Dword));
    z1 = u64::wrapping_add(z1, (a[14] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[6] as Dword));
    z0 = u64::wrapping_sub(z0, (a[6] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[5] = (z0 as Word) & RADIX_MASK;
    c[13] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 6
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[6] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[5] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[4] as Dword) * (b[2] as Dword));
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (b[3] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[4] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[5] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[6] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[6], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], bb[2]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], bb[3]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[4]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[5]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[6]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[14] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[13] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[12] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, (a[11] as Dword) * (b[11] as Dword));
    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[12] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[13] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[14] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], bb[7]));
    z1 = u64::wrapping_add(z1, (a[15] as Dword) * (b[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);
    z0 = u64::wrapping_sub(z0, (a[7] as Dword) * (b[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[6] = (z0 as Word) & RADIX_MASK;
    c[14] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 7
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[7] as Dword) * (b[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[6] as Dword) * (b[1] as Dword));
    z2 = u64::wrapping_add(z2, (a[5] as Dword) * (b[2] as Dword));
    z2 = u64::wrapping_add(z2, (a[4] as Dword) * (b[3] as Dword));
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (b[4] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (b[5] as Dword));
    z2 = u64::wrapping_add(z2, (a[1] as Dword) * (b[6] as Dword));
    z2 = u64::wrapping_add(z2, (a[0] as Dword) * (b[7] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[7], bb[0]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[6], bb[1]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], bb[2]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], bb[3]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], bb[4]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], bb[5]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], bb[6]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[0], bb[7]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, (a[15] as Dword) * (b[8] as Dword));
    z0 = u64::wrapping_add(z0, (a[14] as Dword) * (b[9] as Dword));
    z0 = u64::wrapping_add(z0, (a[13] as Dword) * (b[10] as Dword));
    z0 = u64::wrapping_add(z0, (a[12] as Dword) * (b[11] as Dword));
    z0 = u64::wrapping_add(z0, (a[11] as Dword) * (b[12] as Dword));
    z0 = u64::wrapping_add(z0, (a[10] as Dword) * (b[13] as Dword));
    z0 = u64::wrapping_add(z0, (a[9] as Dword) * (b[14] as Dword));
    z0 = u64::wrapping_add(z0, (a[8] as Dword) * (b[15] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z1 = u64::wrapping_add(z1, z2);
    z0 = u64::wrapping_add(z0, z2);

    c[7] = (z0 as Word) & RADIX_MASK;
    c[15] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    // finish

    z0 = u64::wrapping_add(z0, z1);
    z0 = u64::wrapping_add(z0, c[8] as Dword);
    z1 = u64::wrapping_add(z1, c[0] as Dword);

    c[8] = (z0 as Word) & RADIX_MASK;
    c[0] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    c[9] = u32::wrapping_add(c[9], z0 as Word);
    c[1] = u32::wrapping_add(c[1], z1 as Word);

    c
}

#[cfg(test)]
mod tests {
    use crate::bignumber::deserialize;

    use super::*;

    #[test]
    pub fn test_karatsuba() {
        let (x, _) = deserialize([
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ]);
        let (y, _) = deserialize([
            0x74, 0xa8, 0xbc, 0x39, 0x4b, 0x75, 0xd2, 0x58, 0x2f, 0x2d, 0x90, 0x82, 0xc3, 0xf3,
            0x47, 0x76, 0xc8, 0xbd, 0x0b, 0x68, 0xe1, 0xc0, 0xb9, 0x14, 0x3b, 0x87, 0x4a, 0xd8,
            0x7d, 0xd1, 0x80, 0x65, 0x63, 0x78, 0x76, 0xbf, 0x89, 0x7e, 0xff, 0x1e, 0x8b, 0xc1,
            0x3d, 0xaa, 0xcf, 0x9f, 0x0d, 0x3c, 0x36, 0x72, 0x33, 0x7a, 0xd5, 0x74, 0x81, 0xf5,
        ]);
        let (res, _) = deserialize([
            0x11, 0x95, 0x9c, 0x2e, 0x91, 0x78, 0x6f, 0xec, 0xff, 0x37, 0xe5, 0x8e, 0x2b, 0x50,
            0x9e, 0xf8, 0xfb, 0x41, 0x08, 0xc4, 0xa7, 0x02, 0x1c, 0xbf, 0x5a, 0x9f, 0x18, 0xa7,
            0xec, 0x32, 0x65, 0x7e, 0xed, 0xdc, 0x81, 0x81, 0x80, 0xa8, 0x4c, 0xdd, 0x95, 0x14,
            0xe6, 0x67, 0x26, 0xd3, 0xa1, 0x22, 0xdb, 0xb3, 0x9f, 0x17, 0x7a, 0x85, 0x16, 0x6c,
        ]);
        let z = karatsuba_mul(&x, &y);
        assert_eq!(z, res);
    }
}
