use crate::errors::LibgoldilockErrors;
use crate::{
    bignumber::*,
    constants32::{
        BigNumber, Dword, Sword, Word, BIG_ONE, BIG_ZERO, DECAF_COMB_NUMBER, DECAF_COMB_SPACING,
        DECAF_COMB_TEETH, DECAF_TRUE, EDWARDS_D, FIELD_BYTES, SCALAR_BITS, SCALAR_WORDS, WORD_BITS,
        ZERO_MASK,
    },
    decaf_combs_32::DECAF_PRECOMP_TABLE,
    decaf_wnaf_table::DECAF_WNAF_TABLE,
    scalar::{self, halve, Scalar},
};

#[derive(Debug, PartialEq, Clone)]
pub struct SmvtControl {
    power: i64,
    addend: i64,
}

impl SmvtControl {
    pub fn new() -> Self {
        SmvtControl {
            power: 0,
            addend: 0,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct TwistedExtendedPoint {
    x: BigNumber,
    y: BigNumber,
    z: BigNumber,
    t: BigNumber,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TwistedNiels {
    pub a: BigNumber,
    pub b: BigNumber,
    pub c: BigNumber,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TwistedProjectedNiels {
    pub n: TwistedNiels,
    pub z: BigNumber,
}

impl Default for TwistedProjectedNiels {
    fn default() -> Self {
        TwistedProjectedNiels {
            n: TwistedNiels::new(),
            z: create_zero_bignumber(),
        }
    }
}

impl TwistedProjectedNiels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_extended_point(&self) -> TwistedExtendedPoint {
        let mut q = TwistedExtendedPoint::new();

        let eu = add(&self.n.b, &self.n.a);
        q.y = sub(&self.n.b, &self.n.a);
        q.t = mul(&q.y, &eu);
        q.x = mul(&self.z, &q.y);
        q.y = mul(&self.z, &eu);
        q.z = square(&self.z);

        q
    }
}

impl Default for TwistedExtendedPoint {
    fn default() -> Self {
        TwistedExtendedPoint {
            x: create_zero_bignumber(),
            y: create_zero_bignumber(),
            z: create_zero_bignumber(),
            t: create_zero_bignumber(),
        }
    }
}

impl TwistedExtendedPoint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_identity(&mut self) {
        self.x = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.y = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.z = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        self.t = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    pub fn double_internal(&mut self, before_double: bool) {
        let c = square(&self.x);
        let mut a = square(&self.y);
        // println!("Debug: {:?}", a);
        let d = add_raw(&c, &a);
        self.t = add_raw(&self.x, &self.y);
        let mut b = square(&self.t);
        let mut exponent_bias: Word = 0x03;
        b = sub_x_bias(&b, &d, &exponent_bias);
        self.t = sub(&a, &c);
        self.x = square(&self.z);
        self.z = add_raw(&self.x, &self.x);
        exponent_bias = 0x04;
        a = sub_x_bias(&self.z, &self.t, &exponent_bias);
        self.x = mul(&a, &b);
        self.z = mul(&self.t, &a);
        self.y = mul(&self.t, &d);
        if !before_double {
            self.t = mul(&b, &d)
        }
    }

    pub fn mod_equal(&self, p2: &TwistedExtendedPoint) -> bool {
        let a = mul(&self.y, &p2.x);
        let b = mul(&self.x, &p2.y);
        let valid = decaf_equal(&a, &b);

        valid == DECAF_TRUE
    }

    pub fn add_niels_to_extended(&mut self, np: &TwistedNiels, before_double: bool) {
        let mut b = sub(&self.y, &self.x);
        let mut a = mul(&np.a, &b);
        b = add_raw(&self.x, &self.y);
        self.y = mul(&np.b, &b);
        self.x = mul(&np.c, &self.t);
        let c = add_raw(&a, &self.y);
        b = sub(&self.y, &a);
        self.y = sub(&self.z, &self.x);
        a = add_raw(&self.x, &self.z);
        self.z = mul(&a, &self.y);
        self.x = mul(&self.y, &b);
        self.y = mul(&a, &c);
        if !before_double {
            self.t = mul(&b, &c);
        }
    }

    pub fn sub_niels_from_extended_point(&mut self, np: &TwistedNiels, before_double: bool) {
        let mut b = sub(&self.y, &self.x);
        let mut a = mul(&np.b, &b);
        b = add_raw(&self.x, &self.y);
        self.y = mul(&np.a, &b);
        self.x = mul(&np.c, &self.t);
        let c = add_raw(&a, &self.y);
        b = sub(&self.y, &a);
        self.y = add_raw(&self.z, &self.x);
        a = sub(&self.z, &self.x);
        self.z = mul(&a, &self.y);
        self.x = mul(&self.y, &b);
        self.y = mul(&a, &c);
        if !before_double {
            self.t = mul(&b, &c);
        }
    }

    pub fn add_projected_niels_to_extended(
        &mut self,
        np: &TwistedProjectedNiels,
        before_double: bool,
    ) {
        let tmp = mul(&self.z, &np.z);
        self.z = tmp;
        self.add_niels_to_extended(&np.n, before_double);
    }

    pub fn sub_projected_niels_from_extended_point(
        &mut self,
        p2: &TwistedProjectedNiels,
        before_double: bool,
    ) {
        let tmp = mul(&self.z, &p2.z);
        self.z = tmp;
        self.sub_niels_from_extended_point(&p2.n, before_double);
    }

    pub fn eddsa_like_encode(&self) -> [u8; 57] {
        let mut x = square(&self.x);
        let mut t = square(&self.y);
        let u = add(&x, &t);
        let mut z = add(&self.y, &self.x);
        let mut y = square(&z);
        y = sub(&u, &y);
        z = sub(&t, &x);
        x = square(&self.z);
        t = add(&x, &x);
        t = sub(&t, &z);
        x = mul(&t, &y);
        y = mul(&z, &u);
        z = mul(&u, &t);
        // must zero out temporary variables
        z = invert(&z);
        t = mul(&x, &z);
        x = mul(&y, &z);

        let mut res: [u8; 57] = [0; 57];
        res[0..56].copy_from_slice(&dsa_like_serialize(&x));
        res[56] = (ZERO_MASK & low_bit(&t)) as u8;

        res
    }

    pub fn is_on_curve(&self) -> bool {
        let mut a = mul(&self.x, &self.y);
        let mut b = mul(&self.z, &self.t);
        let mut valid = decaf_equal(&a, &b);

        a = square(&self.x);
        b = square(&self.y);
        a = sub(&b, &a);
        b = square(&self.t);
        let c = mul_w(&b, &((1 - EDWARDS_D) as Dword));
        b = square(&self.z);
        b = sub(&b, &c);
        valid &= decaf_equal(&a, &b);
        valid &= !(decaf_equal(&self.z, &BIG_ZERO));

        valid == DECAF_TRUE
    }

    pub fn to_projected_niels(&self) -> TwistedProjectedNiels {
        let a = sub(&self.y, &self.x);
        let b = add(&self.x, &self.y);
        let c = mul_with_signed_curve_constant(&self.t, &((2 * EDWARDS_D) - 2));
        let z = add(&self.z, &self.z);

        TwistedProjectedNiels {
            n: TwistedNiels { a, b, c },
            z,
        }
    }

    pub fn prepare_fixed_window(&self) -> Vec<TwistedProjectedNiels> {
        let n_table: usize = 16;
        let mut p_original = self.clone();
        let mut p_temp = self.clone();
        p_temp.double_internal(false);
        let pn = p_temp.to_projected_niels();

        let mut out = Vec::new();
        out.push(p_original.to_projected_niels());
        for _i in 1..n_table {
            p_original.add_projected_niels_to_extended(&pn, false);
            out.push(p_original.to_projected_niels());
        }

        out
    }

    pub fn point_scalar_mul(&self, s: &Scalar) -> TwistedExtendedPoint {
        let decaf_window_bits: usize = 5;
        let window: usize = decaf_window_bits;
        let window_mask: usize = (1 << window) - 1;
        let window_tmask: usize = window_mask >> 1;
        let _n_table: usize = 1 << (window - 1);

        let mut out = TwistedExtendedPoint::new();
        let mut scalar1x;
        scalar1x = scalar::add(s, &DECAF_PRECOMP_TABLE.scalar_adjustment);
        scalar1x = halve(scalar1x);

        let multiples = self.prepare_fixed_window();
        let mut first: bool = true;

        let mut i = (SCALAR_BITS - ((SCALAR_BITS - 1) % window) - 1) as i32;
        while i >= 0 {
            let i1 = i as usize;
            let mut bits = scalar1x[i1 / WORD_BITS] >> (i1 % WORD_BITS);

            if i1 % WORD_BITS >= WORD_BITS - window && i1 / WORD_BITS < SCALAR_WORDS - 1 {
                bits ^= scalar1x[i1 / WORD_BITS + 1] << (WORD_BITS - (i1 % WORD_BITS));
            }
            bits &= window_mask as u32;
            let inv = u32::wrapping_sub(bits >> (window - 1), 1);
            bits ^= inv;

            let mut p_neg = multiples[(bits as usize) & window_tmask].clone();
            p_neg.n.conditional_negate(&inv);

            if first {
                out = p_neg.to_extended_point();
                first = false;
            } else {
                for _j in 0..(window - 1) {
                    out.double_internal(true);
                }
                out.double_internal(false);
                out.add_projected_niels_to_extended(&p_neg, false);
            }

            i -= window as i32;
        }
        out
    }

    pub fn point_double_scalamul_non_secret(
        &self,
        scalar_pre: &Scalar,
        scalar_var: &Scalar,
    ) -> TwistedExtendedPoint {
        let mut p = self.clone();

        let table_bits_var: usize = 3; // DECAF_WNAF_VAR_TABLE_BITS
        let table_bits_pre: usize = 5; // DECAF_WNAF_FIXED_TABLE_BITS

        let mut control_var = Vec::new();
        for _i in 0..115 {
            control_var.push(SmvtControl::new());
        }

        let mut control_pre = Vec::new();
        for _i in 0..77 {
            control_pre.push(SmvtControl::new());
        }

        recode_wnaf(&mut control_pre, scalar_pre, table_bits_pre);
        recode_wnaf(&mut control_var, scalar_var, table_bits_var);

        let mut precmp_var = Vec::new();
        for _i in 0..8 {
            precmp_var.push(TwistedProjectedNiels::new());
        }

        decaf_prepare_wnaf_table(&mut precmp_var, &mut p, table_bits_var);

        let mut contp: usize = 0;
        let mut contv: usize = 0;

        let index = control_var[0].addend >> 1;

        let mut i = control_var[0].power;
        let mut out;

        if i > control_pre[0].power {
            out = precmp_var[index as usize].to_extended_point();
            contv += 1;
        } else if i == control_pre[0].power && i >= 0 {
            out = precmp_var[index as usize].to_extended_point();
            out.add_niels_to_extended(
                &DECAF_WNAF_TABLE[(control_pre[0].addend as usize) >> 1],
                i != 0,
            );
            contv += 1;
            contp += 1;
        } else {
            i = control_pre[0].power;
            out = DECAF_WNAF_TABLE[(control_pre[0].addend as usize) >> 1].to_extended();
            contp += 1;
        }

        if i < 0 {
            out.set_identity();
            return out;
        }

        i -= 1;
        while i >= 0 {
            let cv = i == control_var[contv].power;
            let cp = i == control_pre[contp].power;

            out.double_internal(i != 0 && !(cv || cp));

            if cv {
                if control_var[contv].addend > 0 {
                    let a = control_var[contv].addend as usize;
                    out.add_projected_niels_to_extended(&precmp_var[a >> 1], i != 0 && !cp);
                } else {
                    let a = (-control_var[contv].addend) as usize;
                    out.sub_projected_niels_from_extended_point(&precmp_var[a >> 1], i != 0 && !cp);
                }
                contv += 1;
            }

            if cp {
                if control_pre[contp].addend > 0 {
                    let a = control_pre[contp].addend as usize;
                    out.add_niels_to_extended(&DECAF_WNAF_TABLE[a >> 1], i != 0)
                } else {
                    let a = (-control_pre[contp].addend) as usize;
                    out.sub_niels_from_extended_point(&DECAF_WNAF_TABLE[a >> 1], i != 0)
                }
                contp += 1;
            }

            i -= 1;
        }

        out

        // CONTINUE
    }
}

impl Default for TwistedNiels {
    fn default() -> Self {
        TwistedNiels {
            a: create_zero_bignumber(),
            b: create_zero_bignumber(),
            c: create_zero_bignumber(),
        }
    }
}

impl TwistedNiels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn conditional_negate(&mut self, neg: &Word) {
        conditional_swap(&mut self.a, &mut self.b, neg);
        self.c = conditional_negate(&self.c, neg);
    }

    pub fn to_extended(&self) -> TwistedExtendedPoint {
        let mut p = TwistedExtendedPoint::new();
        p.y = add(&self.b, &self.a);
        p.x = sub(&self.b, &self.a);
        p.t = mul(&p.y, &p.x);
        p.z = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        p
    }
}

pub fn trailing_zeroes_32(mut n: u32) -> u32 {
    if n == 0 {
        return 32;
    };
    let mut r: u32 = 0;
    while n % 2 == 0 {
        r += 1;
        n /= 2;
    }
    r
}

pub fn recode_wnaf(control: &mut [SmvtControl], s: &Scalar, table_bits: usize) -> Word {
    let table_size: usize = (446 / (table_bits + 1)) + 3;
    let mut position: usize = table_size - 1;
    let b_over16: usize = 2;

    control[position].power = -1;
    control[position].addend = 0;
    position -= 1;

    let mut current: u64 = (s[0] & 0xffff) as u64;
    let mask: u32 = ((1 << (table_bits + 1)) - 1) as u32;

    for w in 1..30 {
        if w < 28 {
            current += ((s[w / b_over16] >> (16 * (w % b_over16))) << 16) as u64;
        }
        while current & 0xffff != 0 {
            let pos: u32 = trailing_zeroes_32(current as u32);
            let odd: u32 = (current as u32) >> pos;
            let mut delta: i32 = (odd & mask) as i32;
            if odd & (1 << (table_bits + 1)) != 0 {
                delta -= 1 << (table_bits + 1);
            }
            current = ((current as i64) - ((delta << pos) as i64)) as u64;
            control[position].power = (pos as i64) + 16 * ((w as i64) - 1);
            control[position].addend = delta as i64;
            position -= 1;
        }
        current >>= 16;
    }

    position += 1;
    let n: usize = table_size - position;
    for i in 0..n {
        control[i] = control[i + position].clone();
    }
    (n - 1) as Word
}

pub fn decaf_prepare_wnaf_table(
    dst: &mut [TwistedProjectedNiels],
    p: &mut TwistedExtendedPoint,
    table_size: usize,
) {
    dst[0] = p.to_projected_niels();

    if table_size == 0 {
        return;
    }

    p.double_internal(false);

    let tw_op = p.to_projected_niels();

    p.add_projected_niels_to_extended(&dst[0], false);
    dst[1] = p.to_projected_niels();

    dst.iter_mut().take(1 << table_size).skip(2).for_each(|x| {
        p.add_projected_niels_to_extended(&tw_op, false);
        *x = p.to_projected_niels();
    });
}

#[allow(unused_variables)]
#[allow(unused_assignments)]
pub fn eddsa_like_decode(src_org: &[u8]) -> Result<TwistedExtendedPoint, LibgoldilockErrors> {
    let mut p = TwistedExtendedPoint::new();
    if src_org.len() != 57 {
        return Err(LibgoldilockErrors::InvalidLengthError);
    }
    let mut src: [u8; 57] = [0; 57];
    src.copy_from_slice(src_org);
    let cofactor_mask = ZERO_MASK;
    let low = !is_zero_mask(ZERO_MASK & (src[FIELD_BYTES] as Word));
    src[FIELD_BYTES] &= (!cofactor_mask) as u8;

    // TODO: This is never used
    let mut succ = is_zero_mask(src[FIELD_BYTES] as Word);
    let succ1: u32;
    (p.y, succ1) = dsa_like_deserialize(&src, 0);
    // TODO: No use after this
    succ &= succ1;

    p.x = square(&p.y);
    p.z = sub(&BIG_ONE, &p.x);
    p.t = mul_with_signed_curve_constant(&p.x, &EDWARDS_D);
    p.t = sub(&BIG_ONE, &p.t);
    p.x = mul(&p.z, &p.t);
    p.t = isr(&p.x);
    p.x = mul(&p.t, &p.z);
    p.x = decaf_cond_negate(&p.x, &(!(low_bit(&p.x)) ^ low));
    p.z = BIG_ONE;

    let c = square(&p.x);
    let mut a = square(&p.y);
    let d = add(&c, &a);
    p.t = add(&p.y, &p.x);
    let mut b = square(&p.t);
    b = sub(&b, &d);
    p.t = sub(&a, &c);
    p.x = square(&p.z);
    p.z = add(&p.x, &p.x);
    a = sub(&p.z, &d);
    p.x = mul(&a, &b);
    p.z = mul(&p.t, &a);
    p.y = mul(&p.t, &d);
    p.t = mul(&b, &d);

    let ok = p.is_on_curve();
    if !ok {
        return Err(LibgoldilockErrors::DecodeError);
    }

    let mut scalar_one_forth: Scalar = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    scalar_one_forth = halve(scalar_one_forth);
    scalar_one_forth = halve(scalar_one_forth);

    p = p.point_scalar_mul(&scalar_one_forth);

    Ok(p)
}

pub fn precomputed_scalar_mul(s: Scalar) -> TwistedExtendedPoint {
    let mut p = TwistedExtendedPoint::new();
    let mut scalar2 = crate::scalar::add(&s, &DECAF_PRECOMP_TABLE.scalar_adjustment);
    scalar2 = halve(scalar2);

    let mut np;
    for i in (0..(DECAF_COMB_SPACING)).rev() {
        if i != DECAF_COMB_SPACING - 1 {
            p.double_internal(false);
        }

        for j in 0..DECAF_COMB_NUMBER {
            let mut tab: Word = 0;
            for k in 0..DECAF_COMB_TEETH {
                let bit = i + DECAF_COMB_SPACING * (k + j * DECAF_COMB_TEETH);
                if bit < SCALAR_BITS {
                    tab |= (scalar2[bit / WORD_BITS] >> (bit % WORD_BITS) & 1) << k;
                }
            }

            let invert = ((tab as Sword) >> (DECAF_COMB_TEETH - 1)) - 1;
            tab ^= invert as Word;
            tab &= (1 << (DECAF_COMB_TEETH - 1)) - 1;

            let index = (j << (DECAF_COMB_TEETH - 1)) + (tab as usize);
            np = DECAF_PRECOMP_TABLE.lookup(index);
            np.conditional_negate(&(invert as Word));
            if i != (DECAF_COMB_SPACING - 1) || j != 0 {
                p.add_niels_to_extended(&np, (j == DECAF_COMB_NUMBER - 1) && (i != 0));
            } else {
                p = np.to_extended();
            }
        }
    }

    p
}

#[cfg(test)]
mod tests {
    // use crate::{constants32::{fieldBytes, bigOne, bigZero}};

    use crate::constants32::LMASK;

    use super::*;

    #[test]
    pub fn test_double_internal() {
        let mut p = TwistedExtendedPoint {
            x: [
                0x08354b7a, 0x0895b3e8, 0x06ae5175, 0x0644b394, 0x0b7faf9e, 0x0c5237db, 0x013a0c90,
                0x08f5bce0, 0x09a3d79b, 0x00f17559, 0x0de8f041, 0x073e222f, 0x0dc2b7ee, 0x005ac354,
                0x0766db38, 0x065631fe,
            ],
            y: [
                0x00398885, 0x055c9bed, 0x0ae443ca, 0x0fd70ea4, 0x09e2a7d2, 0x04ac2e9d, 0x00678287,
                0x0294768e, 0x0b604cea, 0x07b49317, 0x0dc2a6d9, 0x0e44a6fb, 0x09db3965, 0x049d3bf5,
                0x03e655fe, 0x003a9c02,
            ],
            z: [
                0x0fd57162, 0x0a39f768, 0x03009756, 0x065d735f, 0x0d1da282, 0x0589ecd7, 0x003196b1,
                0x0c001dfe, 0x019f1050, 0x0152e8d2, 0x0c14ff38, 0x00f7a446, 0x028053f6, 0x0f8a91e9,
                0x05a8d694, 0x09d5ae86,
            ],
            t: [
                0x04198f2e, 0x0d82440f, 0x0fce100e, 0x0af4829d, 0x0d5c3516, 0x0094a0da, 0x078cdb39,
                0x0e738836, 0x01ec536d, 0x06dfd1e9, 0x0ee16173, 0x0addc8c0, 0x0797fb1d, 0x059741a3,
                0x0a7f9c34, 0x088fe0a6,
            ],
        };
        let mut exp = TwistedExtendedPoint {
            x: [
                0x00d8f04c, 0x03e54689, 0x0eb4db2b, 0x0887ba34, 0x0a5b4ebc, 0x0f6c0261, 0x03bfa803,
                0x0408ff02, 0x03b4ef26, 0x0465c028, 0x0cd47378, 0x064c55b4, 0x08245850, 0x01912682,
                0x0dcbf92c, 0x07a7fa30,
            ],
            y: [
                0x0d94d1a6, 0x0f7306e8, 0x0278b336, 0x04362b7b, 0x0faf02b9, 0x06b01d18, 0x07a597da,
                0x0bd6add0, 0x047afa98, 0x0e64e897, 0x0bbf88e6, 0x01d0a534, 0x04a52b9d, 0x0af374e0,
                0x05091d54, 0x00fcf1a5,
            ],
            z: [
                0x042318ce, 0x04aecdae, 0x0e8f196b, 0x0019d2e3, 0x045d147c, 0x060b153e, 0x0adf2c37,
                0x0419cdd8, 0x06d19046, 0x00d18821, 0x06c7b9c2, 0x0c0ffd68, 0x0b7e4ca2, 0x06da0d56,
                0x0952b40f, 0x03008395,
            ],
            t: [
                0x04643593, 0x000e0fdd, 0x013f29f3, 0x0bb8992d, 0x0a30d344, 0x09151eec, 0x0d12bb82,
                0x05c7a054, 0x0103c2c6, 0x08a61fe2, 0x0aced4bf, 0x0f76d481, 0x0db774be, 0x065ef8a8,
                0x0ff47a71, 0x0f49f73e,
            ],
        };
        p.double_internal(false);
        assert_eq!(p, exp);

        p = TwistedExtendedPoint {
            x: [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            y: [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            z: [0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            t: [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        exp = TwistedExtendedPoint {
            x: [
                0x0000003b, 0x10000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            y: [
                0x0000000e, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            z: [
                0x0000002c, 0x10000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            t: [
                0x00000002, 0x10000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
        };
        p.double_internal(true);
        assert_eq!(p, exp);
    }

    #[test]
    pub fn test_conditional_negate() {
        let pa: BigNumber = must_deserialize([
            0x4b, 0x8a, 0x63, 0x2c, 0x1f, 0xea, 0xb7, 0x27, 0x69, 0xcd, 0x96, 0xe7, 0xaa, 0xa5,
            0x77, 0x86, 0x18, 0x71, 0xb3, 0x61, 0x39, 0x45, 0xc8, 0x02, 0xb8, 0x93, 0x77, 0xe8,
            0xb8, 0x53, 0x31, 0xec, 0xc0, 0xff, 0xb1, 0xcb, 0x20, 0x16, 0x9b, 0xfc, 0x9c, 0x27,
            0x27, 0x4d, 0x38, 0xb0, 0xd0, 0x1e, 0x87, 0xa1, 0xd5, 0xd8, 0x51, 0x77, 0x0b, 0xc8,
        ]);
        let pb: BigNumber = must_deserialize([
            0x81, 0xa4, 0x5f, 0x02, 0xf4, 0x10, 0x53, 0xf8, 0xd7, 0xd2, 0xa1, 0xf1, 0x76, 0xa3,
            0x40, 0x52, 0x9b, 0x33, 0xb7, 0xee, 0x4d, 0x3f, 0xa8, 0x4d, 0xe3, 0x84, 0xb7, 0x50,
            0xb3, 0x5a, 0x54, 0xc3, 0x15, 0xbf, 0x36, 0xc4, 0x1d, 0x02, 0x3a, 0xde, 0x22, 0x64,
            0x49, 0x91, 0x6e, 0x66, 0x83, 0x96, 0x58, 0x9e, 0xa2, 0x14, 0x5d, 0xa0, 0x9b, 0x95,
        ]);
        let pc: BigNumber = must_deserialize([
            0x5f, 0x5a, 0x2b, 0x06, 0xa2, 0xdb, 0xf7, 0x13, 0x6f, 0x8d, 0xc9, 0x79, 0xfd, 0x54,
            0xd6, 0x31, 0xca, 0x7d, 0xe5, 0x03, 0x97, 0x25, 0x0a, 0x19, 0x6d, 0x3b, 0xe2, 0xa7,
            0x21, 0xab, 0x7c, 0xba, 0xa9, 0x2c, 0x54, 0x5d, 0x9b, 0x15, 0xb5, 0x31, 0x9e, 0x11,
            0xb6, 0x4b, 0xc0, 0x31, 0x66, 0x60, 0x49, 0xd8, 0x63, 0x7e, 0x13, 0x83, 0x8b, 0x3b,
        ]);
        let mut n = TwistedNiels {
            a: pa.clone(),
            b: pb.clone(),
            c: pc.clone(),
        };
        let n_neg = TwistedNiels {
            a: pb.clone(),
            b: pa.clone(),
            c: neg(&pc.clone()),
        };
        n.conditional_negate(&LMASK);
        assert_eq!(n, n_neg);
    }

    #[test]
    pub fn test_add_niels_to_extended() {
        let mut p = TwistedExtendedPoint {
            x: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            y: [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            z: [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            t: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let q = TwistedNiels {
            a: [
                0x068d5b74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
            b: [
                0x068d5b74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
            c: [
                0x068d5b74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
        };
        let mut exp = TwistedExtendedPoint {
            x: [
                0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            y: [
                0x0d1ab6e7, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            z: [
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            t: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        p.add_niels_to_extended(&q, true);
        assert_eq!(p, exp);

        let mut r = TwistedExtendedPoint {
            x: [
                0x00d8f04c, 0x03e54689, 0x0eb4db2b, 0x0887ba34, 0x0a5b4ebc, 0x0f6c0261, 0x03bfa803,
                0x0408ff02, 0x03b4ef26, 0x0465c028, 0x0cd47378, 0x064c55b4, 0x08245850, 0x01912682,
                0x0dcbf92c, 0x07a7fa30,
            ],
            y: [
                0x0d94d1a6, 0x0f7306e8, 0x0278b336, 0x04362b7b, 0x0faf02b9, 0x06b01d18, 0x07a597da,
                0x0bd6add0, 0x047afa98, 0x0e64e897, 0x0bbf88e6, 0x01d0a534, 0x04a52b9d, 0x0af374e0,
                0x05091d54, 0x00fcf1a5,
            ],
            z: [
                0x042318ce, 0x04aecdae, 0x0e8f196b, 0x0019d2e3, 0x045d147c, 0x060b153e, 0x0adf2c37,
                0x0419cdd8, 0x06d19046, 0x00d18821, 0x06c7b9c2, 0x0c0ffd68, 0x0b7e4ca2, 0x06da0d56,
                0x0952b40f, 0x03008395,
            ],
            t: [
                0x04643593, 0x000e0fdd, 0x013f29f3, 0x0bb8992d, 0x0a30d344, 0x09151eec, 0x0d12bb82,
                0x05c7a054, 0x0103c2c6, 0x08a61fe2, 0x0aced4bf, 0x0f76d481, 0x0db774be, 0x065ef8a8,
                0x0ff47a71, 0x0f49f73e,
            ],
        };
        let np = TwistedNiels {
            a: [
                0x08fcb20f, 0x04611087, 0x01cc6f32, 0x0df43db2, 0x04516644, 0x0ffdde9f, 0x091686b9,
                0x05199177, 0x0fd34473, 0x0b72b441, 0x0cb1c72b, 0x08d45684, 0x00fc17a5, 0x01518137,
                0x007f74d3, 0x0a456d13,
            ],
            b: [
                0x09b607dc, 0x01430f14, 0x016715fc, 0x0e992ccd, 0x00a32a09, 0x0a62209b, 0x0c26b8e4,
                0x0b889ced, 0x0ac109cf, 0x059bf9a3, 0x0b7feac2, 0x06871bb3, 0x0d9a0e6b, 0x0f4a4d5f,
                0x00cd69a5, 0x0b95db46,
            ],
            c: [
                0x08bda702, 0x03630441, 0x01561558, 0x07bc5686, 0x0e30416f, 0x0f344bc8, 0x080f59d7,
                0x0a645370, 0x07d00ace, 0x0b4c2007, 0x0b26f8cc, 0x0ee79620, 0x00b5403d, 0x0a6a558e,
                0x066f3d19, 0x08f1d2c7,
            ],
        };
        exp = TwistedExtendedPoint {
            x: [
                0x0662c9a5, 0x0e2bc383, 0x09b2fc38, 0x0042d545, 0x0431bbe8, 0x09e2a364, 0x03b8e92e,
                0x0df6d043, 0x07136f20, 0x00bde4fe, 0x0ca79859, 0x0c484320, 0x099507c4, 0x0ef683e6,
                0x09f8221d, 0x0b1fdcb8,
            ],
            y: [
                0x0aaf871f, 0x08fcadaf, 0x0974aaea, 0x07d73c92, 0x0bdaba0c, 0x069d1bf6, 0x0906e75c,
                0x0020e493, 0x07a2e1ec, 0x06e27878, 0x00e9c9d2, 0x08e429f5, 0x026f7c86, 0x0420e6c5,
                0x0304fccb, 0x0599fe0e,
            ],
            z: [
                0x01b26129, 0x071c89cf, 0x0b012391, 0x0074b87c, 0x0331b5fb, 0x0a2cbc8d, 0x0d1a4729,
                0x0ab451d3, 0x0308cad6, 0x0e086c2b, 0x03bd396c, 0x0cd2bd87, 0x0910f41c, 0x090be75a,
                0x0a8d7a0e, 0x07ec7ea8,
            ],
            t: [
                0x08b7d023, 0x05bc6276, 0x03e2082d, 0x09d3eba3, 0x0ecc2af3, 0x07a4c7be, 0x08ca49b8,
                0x0ebe1040, 0x0cf6ddeb, 0x015ec1ff, 0x010eed61, 0x0882e84d, 0x07fefb78, 0x0d97e204,
                0x02e940a1, 0x0537d7c0,
            ],
        };
        r.add_niels_to_extended(&np, false);
        assert_eq!(r, exp);
    }

    #[test]
    pub fn test_precomputed_scalarmul() {
        let scalar: Scalar = [0; 14];
        let p = precomputed_scalar_mul(scalar);
        let exp = TwistedExtendedPoint {
            x: [
                0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
            y: [
                0x0b1ff82e, 0x05e98b74, 0x000cecf1, 0x0277711a, 0x0f9b17c5, 0x0c98aadc, 0x05b06211,
                0x0bc17782, 0x0809fef2, 0x08bb648f, 0x0323239f, 0x0d37d81d, 0x0389402c, 0x0cbabc81,
                0x087aaae9, 0x01b50b05,
            ],
            z: [
                0x04e007d1, 0x0a16748b, 0x0ff3130e, 0x0d888ee5, 0x0064e83a, 0x03675523, 0x0a4f9dee,
                0x043e887d, 0x07f6010c, 0x07449b70, 0x0cdcdc60, 0x02c827e2, 0x0c76bfd3, 0x0345437e,
                0x07855516, 0x0e4af4fa,
            ],
            t: [
                0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
                0x0fffffff, 0x0fffffff,
            ],
        };
        assert_eq!(p.x, exp.x);
        assert_eq!(p.t, exp.t);
    }

    #[test]
    pub fn test_is_valid_point() {
        let mut p = TwistedExtendedPoint::new();
        p.x = [
            0x034365c8, 0x06b2a874, 0x0eb875d7, 0x0ae4c7a7, 0x0785df04, 0x09929351, 0x01fe8c3b,
            0x0f2a0e5f, 0x0111d39c, 0x07ab52ba, 0x01df4552, 0x01d87566, 0x0f297be2, 0x027c090f,
            0x0a81b155, 0x0d1a562b,
        ];
        p.y = [
            0x00da9708, 0x0e7d583e, 0x0dbcc099, 0x0d2dad89, 0x05a49ce4, 0x01cb4ddc, 0x0928d395,
            0x0098d91d, 0x0bff16ce, 0x06f02f9a, 0x0ce27cc1, 0x0dab5783, 0x0b553d94, 0x03251a0c,
            0x064d70fb, 0x07fe3a2f,
        ];
        p.z = [
            0x0d5237cc, 0x0319d105, 0x02ab2df5, 0x022e9736, 0x0d79742f, 0x00688712, 0x012d3a65,
            0x0ef4925e, 0x0bd0d260, 0x0832b532, 0x05faef27, 0x01ffe567, 0x0161ce73, 0x07bda0f5,
            0x035d04f1, 0x0930f532,
        ];
        p.t = [
            0x01f6cc27, 0x09be7b8a, 0x0226da79, 0x0f6202f1, 0x0e7264dc, 0x0d25aeb1, 0x06c81f07,
            0x03c32cdc, 0x0923c854, 0x0cfc9865, 0x055b2fed, 0x05bdcc90, 0x01a99835, 0x0ea08056,
            0x0abbf763, 0x03826c2f,
        ];
        assert_eq!(p.is_on_curve(), true);
        p.x = [
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
        ];
        p.y = [
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
        ];
        p.z = [
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
        ];
        p.t = [
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
        ];
        assert_eq!(p.is_on_curve(), false);
    }

    #[test]
    pub fn test_eddsa_like_decode() {
        let ser: [u8; 57] = [
            0xa5, 0xd9, 0xce, 0xa4, 0x06, 0x89, 0xa4, 0x13, 0x94, 0xf0, 0x69, 0x32, 0xfe, 0xe0,
            0xdb, 0x11, 0x7b, 0xe0, 0x75, 0x78, 0x68, 0x2c, 0x48, 0x44, 0x70, 0x3b, 0xe9, 0xc6,
            0x64, 0xde, 0x6c, 0xe0, 0xd6, 0xa5, 0xa3, 0x4e, 0xe7, 0x38, 0xd9, 0xb3, 0x0c, 0x93,
            0x75, 0x75, 0x8d, 0xe8, 0x50, 0xde, 0x06, 0x2c, 0xb9, 0x75, 0x50, 0x7d, 0x24, 0x85,
            0x00,
        ];
        let mut scalar_one_forth: Scalar = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        scalar_one_forth = halve(scalar_one_forth);
        scalar_one_forth = halve(scalar_one_forth);
        let mut exp = TwistedExtendedPoint::new();
        exp.x = [
            0x0c7e3738, 0x0cbdc97c, 0x0d8e25f0, 0x03332483, 0x0111e7fc, 0x0c4b6cc7, 0x0f8f792c,
            0x0bfabfc9, 0x06401561, 0x008bed52, 0x029a6321, 0x0093629d, 0x07cc65ec, 0x0a0306c6,
            0x09cdac09, 0x01124131,
        ];
        exp.y = [
            0x0c35f413, 0x0bea33bb, 0x0a35ff5e, 0x0db8b320, 0x0decf793, 0x0ce8a106, 0x0b6ca51d,
            0x0454dc1c, 0x005424ab, 0x0e976ae4, 0x091a6deb, 0x0780e161, 0x0384d250, 0x00c5041e,
            0x0bef5512, 0x0d39b7a4,
        ];
        exp.z = [
            0x01bff100, 0x01ba8567, 0x078a886e, 0x01a59234, 0x0f7c2f29, 0x0507cdc8, 0x03211d38,
            0x0ecf7fb8, 0x08d25fe3, 0x0445a223, 0x039c7188, 0x0d6f989c, 0x0722cff6, 0x0f0beee0,
            0x0438ebd1, 0x0f3114e2,
        ];
        exp.t = [
            0x059c1192, 0x0a24f740, 0x09f8d723, 0x0db5fd8b, 0x08e6159b, 0x00b004e2, 0x06f2f030,
            0x035c4c38, 0x01387946, 0x0355e067, 0x07d3e614, 0x09d57b9c, 0x03b0c3d7, 0x07002ba2,
            0x0f4e320f, 0x03eafa71,
        ];
        exp = exp.point_scalar_mul(&scalar_one_forth);
        let res = eddsa_like_decode(&ser);
        assert_eq!(res.unwrap(), exp);
        // assert_eq!(suc, decafTrue);
    }
}
