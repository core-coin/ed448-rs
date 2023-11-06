use crate::errors::LibgoldilockErrors;

pub trait PrehashSigner<S> {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<S, LibgoldilockErrors>;
}