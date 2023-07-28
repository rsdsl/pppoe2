pub use error::*;

use std::ffi::{c_int, CString};
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;

use ppproperly::MacAddr;
use socket2::Socket;

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(unused)]
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
    let hwaddr = vec![0; libc::ETH_ALEN as usize - 1];

    let fd = unsafe { internal::pppoe2_create_discovery_socket(ifname, hwaddr[0] as *mut i8) };

    let _ = unsafe { CString::from_raw(ifname) };

    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let sock = unsafe { Socket::from_raw_fd(fd) };

    Ok((sock, <[u8; 6]>::try_from(hwaddr.as_slice())?.into()))
}

pub fn new_session(
    interface: &str,
    remote: MacAddr,
    session_id: u16,
) -> Result<(Socket, File, File)> {
    let ifname = CString::new(interface)?.into_raw();
    let hwaddr = CString::new(remote.0)?.into_raw();
    let sid: c_int = session_id.into();
    let mut ctlfd = c_int::default();
    let mut pppdevfd = c_int::default();

    let fd = unsafe {
        internal::pppoe2_create_if_and_session_socket(
            ifname,
            hwaddr,
            sid,
            &mut ctlfd,
            &mut pppdevfd,
        )
    };

    let _ = unsafe { CString::from_raw(ifname) };
    let _ = unsafe { CString::from_raw(hwaddr) };

    if fd < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let sock = unsafe { Socket::from_raw_fd(fd) };
    let ctl = unsafe { File::from_raw_fd(ctlfd) };
    let ppp_dev = unsafe { File::from_raw_fd(pppdevfd) };

    Ok((sock, ctl, ppp_dev))
}
