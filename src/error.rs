use std::io;

use thiserror::Error;

/// Any pppoe2 or library error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("ppproperly: {0}")]
    Ppproperly(#[from] ppproperly::Error),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("rsdsl_pppoe2_sys: {0}")]
    RsdslPppoe2Sys(#[from] rsdsl_pppoe2_sys::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
