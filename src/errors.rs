use std::fmt;
use std::error::Error;

#[derive(Debug, PartialEq)]
pub enum LibgoldilockErrors {
    DecodeError,
    DecodePubkeyError,
    DecodeSignatureError,
    InvalidLengthError,
    InvalidPubkeyLengthError,
    InvalidSignatureLengthError,
    InvalidSignatureError,
}

impl fmt::Display for LibgoldilockErrors {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> { 
        todo!() 
    }
}

impl Error for LibgoldilockErrors {}