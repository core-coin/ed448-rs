use crate::constants32::{BigNumber, Dword, Word, N_LIMBS, RADIX_MASK};

pub fn karatsuba_square(a: &BigNumber) -> BigNumber {
    let mut aa = [0 as Dword; 8];
    let mut c = [0 as Word; N_LIMBS];

    aa[0] = u64::wrapping_add(a[0] as Dword, a[8] as Dword); // 0 - 8
    aa[1] = u64::wrapping_add(a[1] as Dword, a[9] as Dword); // 1 - 9
    aa[2] = u64::wrapping_add(a[2] as Dword, a[10] as Dword);
    aa[3] = u64::wrapping_add(a[3] as Dword, a[11] as Dword);
    aa[4] = u64::wrapping_add(a[4] as Dword, a[12] as Dword);
    aa[5] = u64::wrapping_add(a[5] as Dword, a[13] as Dword);
    aa[6] = u64::wrapping_add(a[6] as Dword, a[14] as Dword);
    aa[7] = u64::wrapping_add(a[7] as Dword, a[15] as Dword); //7 - 15

    //j = 0
    let mut z2: Dword = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[0] as Dword, a[0] as Dword));
    let mut z1: Dword = u64::wrapping_mul(aa[0], aa[0]);
    z1 = u64::wrapping_sub(z1, z2);
    let mut z0: Dword = u64::wrapping_mul(a[8] as Dword, a[8] as Dword);
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[1]) << 1); // (a7+a15) * (a1+a9)
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], aa[2]) << 1); // (a6+a14) * (a2+a10)
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], aa[3]) << 1); // (a5+a13) * (a3+a11)
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[4], aa[4]));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[9] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[14] as Dword, a[10] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[13] as Dword, a[11] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[12] as Dword, a[12] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[1] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[6] as Dword, a[2] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[5] as Dword, a[3] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[4] as Dword, a[4] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[0] = (z0 as Word) & RADIX_MASK;
    c[8] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 1
    z2 = u64::wrapping_mul(a[1] as Dword, a[0] as Dword) << 1;

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], aa[0]) << 1);
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[9] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[2]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], aa[3]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], aa[4]));
    z2 <<= 1;

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[10] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[14] as Dword, a[11] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[13] as Dword, a[12] as Dword) << 1);
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[2] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[6] as Dword, a[3] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[5] as Dword, a[4] as Dword) << 1);
    z0 = u64::wrapping_add(z0, z2);

    c[1] = (z0 as Word) & RADIX_MASK;
    c[9] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 2
    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[2] as Dword, a[0] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[1] as Dword, a[1] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[1], aa[1]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[10] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[9] as Dword, a[9] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[3]));
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], aa[4]));
    z2 <<= 1;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[5], aa[5]));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[11] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[14] as Dword, a[12] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[13] as Dword, a[13] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[3] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[6] as Dword, a[4] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[5] as Dword, a[5] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[2] = (z0 as Word) & RADIX_MASK;
    c[10] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 3
    z2 = 0;
    z2 = u64::wrapping_add(z2, (a[3] as Dword) * (a[0] as Dword));
    z2 = u64::wrapping_add(z2, (a[2] as Dword) * (a[1] as Dword));
    z2 <<= 1;

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], aa[1]) << 1);
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[11] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[10] as Dword, a[9] as Dword) << 1);
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[4]) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], aa[5]) << 1);

    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[4] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[6] as Dword, a[5] as Dword) << 1);
    z0 = u64::wrapping_add(z0, z2);

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[12] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[14] as Dword, a[13] as Dword) << 1);
    z1 = u64::wrapping_add(z1, z2);

    c[3] = (z0 as Word) & RADIX_MASK;
    c[11] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 4
    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[4] as Dword, a[0] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[3] as Dword, a[1] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[2] as Dword, a[2] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], aa[1]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[2], aa[2]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[12] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[11] as Dword, a[9] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[10] as Dword, a[10] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[5]) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[6], aa[6]));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[13] as Dword) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[14] as Dword, a[14] as Dword));
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[5] as Dword) << 1);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[6] as Dword, a[6] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[4] = (z0 as Word) & RADIX_MASK;
    c[12] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 5
    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[5] as Dword, a[0] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[4] as Dword, a[1] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[3] as Dword, a[2] as Dword) << 1);

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], aa[1]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], aa[2]) << 1);
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[13] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[12] as Dword, a[9] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[11] as Dword, a[10] as Dword) << 1);
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[6]) << 1);

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[14] as Dword) << 1);
    z1 = u64::wrapping_add(z1, z2);

    z0 = u64::wrapping_sub(z0, ((a[7] as Dword) * (a[6] as Dword)) << 1);
    z0 = u64::wrapping_add(z0, z2);

    c[5] = (z0 as Word) & RADIX_MASK;
    c[13] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 6
    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[6] as Dword, a[0] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[5] as Dword, a[1] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[4] as Dword, a[2] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[3] as Dword, a[3] as Dword));

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[6], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], aa[1]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], aa[2]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[3], aa[3]));
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[14] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[13] as Dword, a[9] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[12] as Dword, a[10] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[11] as Dword, a[11] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(aa[7], aa[7]));
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(a[15] as Dword, a[15] as Dword));
    z1 = u64::wrapping_add(z1, z2);
    z0 = u64::wrapping_sub(z0, u64::wrapping_mul(a[7] as Dword, a[7] as Dword));
    z0 = u64::wrapping_add(z0, z2);

    c[6] = (z0 as Word) & RADIX_MASK;
    c[14] = (z1 as Word) & RADIX_MASK;

    z0 >>= 28;
    z1 >>= 28;

    //j = 7
    z2 = 0;
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[7] as Dword, a[0] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[6] as Dword, a[1] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[5] as Dword, a[2] as Dword) << 1);
    z2 = u64::wrapping_add(z2, u64::wrapping_mul(a[4] as Dword, a[3] as Dword) << 1);

    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[7], aa[0]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[6], aa[1]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[5], aa[2]) << 1);
    z1 = u64::wrapping_add(z1, u64::wrapping_mul(aa[4], aa[3]) << 1);
    z1 = u64::wrapping_sub(z1, z2);

    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[15] as Dword, a[8] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[14] as Dword, a[9] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[13] as Dword, a[10] as Dword) << 1);
    z0 = u64::wrapping_add(z0, u64::wrapping_mul(a[12] as Dword, a[11] as Dword) << 1);
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

    use crate::{bignumber::deserialize, karatsuba_32::karatsuba_mul};
    use super::*;

    #[test]
    pub fn test_karatsuba_square() {
        let (x, _) = deserialize([
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ]);
        let (y, _) = deserialize([
            0xf5, 0x81, 0x74, 0xd5, 0x7a, 0x33, 0x72, 0x36, 0x3c, 0x0d, 0x9f, 0xcf, 0xaa, 0x3d,
            0xc1, 0x8b, 0x1e, 0xff, 0x7e, 0x89, 0xbf, 0x76, 0x78, 0x63, 0x65, 0x80, 0xd1, 0x7d,
            0xd8, 0x4a, 0x87, 0x3b, 0x14, 0xb9, 0xc0, 0xe1, 0x68, 0x0b, 0xbd, 0xc8, 0x76, 0x47,
            0xf3, 0xc3, 0x82, 0x90, 0x2d, 0x2f, 0x58, 0xd2, 0x75, 0x4b, 0x39, 0xbc, 0xa8, 0x74,
        ]);
        let z1 = karatsuba_mul(&x, &y);
        let z2 = karatsuba_square(&x);
        assert_eq!(z1, z2);
    }
}
