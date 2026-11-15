//! The OS CSPRNG (getrandom(2)), as fallible fixed-size draws.

use crate::error::{Result, SealError};

pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| SealError::Random) // audit-allow: getrandom errno is not actionable; SealError::Random is the typed form
}

pub(crate) fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
