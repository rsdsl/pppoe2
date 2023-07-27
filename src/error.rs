use std::io;

use thiserror::Error;

/// Any pppoe2 or library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("rsdsl_pppoe2_sys: {0}")]
    RsdslPppoe2Sys(#[from] rsdsl_pppoe2_sys::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
