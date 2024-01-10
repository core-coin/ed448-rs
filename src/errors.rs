use thiserror::Error;

#[derive(Debug, Error)]
pub enum LibgoldilockErrors {
    #[error("DecodeErrro")]
    DecodeError,

    #[error("DecodePubkeyError")]
    DecodePubkeyError,

    #[error("DecodeSignatureError")]
    DecodeSignatureError,

    #[error("InvalidLengthError")]
    InvalidLengthError,

    #[error("Invalid PrivateKey Length, expected: 57 bytes, got: {0} bytes")]
    InvalidPrivKeyLengthErrro(usize),

    #[error("InvalidPubkeyLengthError")]
    InvalidPubkeyLengthError,

    #[error("InvalidSignatureLengthError")]
    InvalidSignatureLengthError,

    #[error("InvalidSignatureError")]
    InvalidSignatureError,
}
