pub use error::*;

use std::ffi::CString;
use std::os::fd::FromRawFd;

use ppproperly::MacAddr;
use socket2::Socket;

mod internal {
    include!(concat!(env!("OUT_DIR"), "/pppoe2_bindings.rs"));
}

pub mod error {
    use std::{array, ffi, io};

    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum Error {
        #[error("nul termination: {0}")]
        Nul(#[from] ffi::NulError),
        #[error("io: {0}")]
        Io(#[from] io::Error),
        #[error("array type conversion: {0}")]
        TryFromSlice(#[from] array::TryFromSliceError),
    }

    pub type Result<T> = std::result::Result<T, Error>;
}

pub fn new_discovery_socket(interface: &str) -> Result<(Socket, MacAddr)> {
    let ifname = CString::new(interface)?.into_raw();
    let hwaddr = CString::new([0; libc::IFNAMSIZ])?.into_raw();

    let fd = unsafe { internal::pppoe2_create_discovery_socket(ifname, hwaddr) };

    let _ = unsafe { CString::from_raw(ifname) };
    let hwaddr = unsafe { CString::from_raw(hwaddr) };

    let sock = unsafe { Socket::from_raw_fd(fd) };

    Ok((sock, <[u8; 6]>::try_from(hwaddr.as_bytes())?.into()))
}
