#![allow(dead_code)]
pub type Word = u32;
pub type Sword = i32;
pub type Dword = u64;
pub type Sdword = i64;

pub const LMASK: Word = 0xffffffff;
pub const ZERO_MASK: Word = 0x80;
pub const ALL_ZEROS: Word = 0x00;
pub const ALL_ONES: Word = 0xffffffff;

pub const DECAF_TRUE: Word = 0xffffffff;
pub const DECAF_FALSE: Word = 0x00;

pub const N_LIMBS: usize = 16;
pub const SCALAR_LIMBS: usize = 14;
pub const RADIX: usize = 28;
pub const RADIX_MASK: Word = 0xfffffff as Word;

pub const EDWARDS_D: Sdword = -39081;

pub type BigNumber = [Word; N_LIMBS];
pub type Serialized = [u8; FIELD_BYTES];

const FIELD_BITS: usize = 448;
//const edwardsD: usize  = -39081;
//const twistedD: usize  = (edwardsD) - 1;
pub const EFF_D: usize = 39082;

pub const FIELD_BYTES: usize = FIELD_BITS / 8; // 56
pub const SCALAR_SER_BYTES: usize = 56;
pub const DSA_FIELD_BYTES: usize = 57;
pub const X448_FIELD_BYTES: usize = 56;
pub const X448_FIELD_BITS: usize = 448;

// The size of the Goldilocks scalars, in bits.
pub const SCALAR_BITS: usize = FIELD_BITS - 2; // 446
                                               // The size of the Goldilocks field, in bytes.
pub const SCALAR_BYTES: usize = (SCALAR_BITS + 7) / 8; // 56

pub const WORD_BITS: usize = 32; // 32-bits

pub const SCALAR_WORDS: usize = (SCALAR_BITS + WORD_BITS - 1) / WORD_BITS;

pub const DECAF_COMB_NUMBER: usize = 0x05;
pub const DECAF_COMB_TEETH: usize = 0x05;
pub const DECAF_COMB_SPACING: usize = 0x12;

pub const MONTGOMERY_FACTOR: Word = 0xae918bc5 as Word;

pub const BIG_ZERO: BigNumber = [0; N_LIMBS];
pub const BIG_ONE: BigNumber = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const BIG_TWO: BigNumber = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const SCALAR_Q: [Word; SCALAR_WORDS] = [
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
];
pub const SCALAR_R2: [Word; SCALAR_WORDS] = [
    0x049b9b60, 0xe3539257, 0xc1b195d9, 0x7af32c4b, 0x88ea1859, 0x0d66de23, 0x5ee4d838, 0xae17cf72,
    0xa3c47c44, 0x1a9cc14b, 0xe4d070af, 0x2052bcb7, 0xf823b729, 0x3402a939,
];
pub const SCALAR_ZERO: [Word; SCALAR_WORDS] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const MODULUS: BigNumber = [
    0xffffff, 0xffffffff, 0xffffff, 0xffffffff, 0xffffff, 0xffffffff, 0xffffff, 0xffffffff,
    0xfffffe, 0xffffffff, 0xffffff, 0xffffffff, 0xffffff, 0xffffffff, 0xffffff, 0xffffffff,
];
