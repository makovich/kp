use crate::pwd::Pwd;

use std::fmt;
use std::path::Path;

impl Keyring {
    pub fn from_db_path(file: impl AsRef<Path>) -> Result<Self, String> {
        let (service, username) = create_from(&file.as_ref().to_string_lossy());
        Keyring::new(service, username)
    }
}

fn create_from(filename: &str) -> (String, String) {
    let service = format!("{}.keepass.cli.tool", crate::BIN_NAME);
    let username = format!("{}", hash(filename));

    (service, username)
}

fn hash(data: &str) -> u64 {
    use std::ops::BitXor;

    // djb2 hash function
    data.as_bytes()
        .iter()
        .fold(1153, |acc, &chr| acc.wrapping_mul(33).bitxor(chr as u64))
}

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "macos")]
pub struct Keyring {
    keyname: String,
    account: String,
    keychain: SecKeychain,
}

#[cfg(target_os = "macos")]
impl fmt::Display for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "name: {}, account: {})", self.keyname, self.account)
    }
}

#[cfg(target_os = "macos")]
impl Keyring {
    fn new(keyname: String, account: String) -> Result<Self, String> {
        SecKeychain::default()
            .map(|keychain| Keyring {
                keyname,
                account,
                keychain,
            })
            .map_err(|e| format!("{}", e))
    }

    pub fn get_password(&self) -> Result<Pwd, String> {
        self.keychain
            .find_generic_password(&self.keyname, &self.account)
            .map(|(pwd, _)| unsafe { String::from_utf8_unchecked(pwd.to_owned()) })
            .map(Pwd::from)
            .map_err(|e| format!("{}", e))
    }

    pub fn set_password(&self, password: &str) -> Result<(), String> {
        self.keychain
            .set_generic_password(&self.keyname, &self.account, password.as_bytes())
            .map_err(|e| format!("{}", e))
    }

    pub fn delete_password(&self) -> Result<(), String> {
        self.keychain
            .find_generic_password(&self.keyname, &self.account)
            .map(|(_, key)| key.delete())
            .map_err(|e| format!("{}", e))
    }
}

#[cfg(target_os = "linux")]
use libc::{c_char, c_int, syscall, SYS_add_key, SYS_keyctl, SYS_request_key};

#[cfg(target_os = "linux")]
use std::{ffi::CString, io, ptr};

#[cfg(target_os = "linux")]
use log::*;

#[cfg(target_os = "linux")]
pub struct Keyring {
    desc: CString,
}

#[cfg(target_os = "linux")]
impl Keyring {
    fn new(keyname: String, account: String) -> Result<Self, String> {
        let desc = [keyname, account].join(":").into_bytes();
        let desc = unsafe { CString::from_vec_unchecked(desc) };

        Ok(Keyring { desc })
    }

    pub fn get_password(&self) -> Result<Pwd, String> {
        const KEYCTL_READ: c_int = 11;

        let pwd = unsafe {
            let err = Err("no key found in keyring".to_owned());

            let key_id = match syscall(
                SYS_request_key,
                b"user\0", // type for user-defined keyrings
                self.desc.as_ptr(),
                ptr::null::<c_char>(),
                0,
            ) {
                -1 => {
                    info!("keyctl key decription: {:?}", self.desc);
                    info!("errno: {:?}", io::Error::last_os_error());
                    return err;
                }
                val => val,
            };

            let data_len = match syscall(SYS_keyctl, KEYCTL_READ, key_id, ptr::null::<c_char>(), 0)
            {
                -1 => {
                    info!("errno: {:?}", io::Error::last_os_error());
                    return err;
                }
                val => val,
            };

            let mut data = vec![0u8; data_len as usize];

            if -1 == syscall(SYS_keyctl, KEYCTL_READ, key_id, data.as_mut_ptr(), data_len) {
                info!("errno: {:?}", io::Error::last_os_error());
                return err;
            }

            String::from_utf8_unchecked(data)
        };

        Ok(pwd.into())
    }

    pub fn set_password(&self, password: &str) -> Result<(), String> {
        const KEY_SPEC_SESSION_KEYRING: c_int = -3;

        unsafe {
            if -1
                == syscall(
                    SYS_add_key,
                    b"user\0",
                    self.desc.as_ptr(),
                    password.as_ptr(),
                    password.len(),
                    KEY_SPEC_SESSION_KEYRING,
                )
            {
                info!("keyctl key decription: {:?}", self.desc);
                info!("errno: {:?}", io::Error::last_os_error());
                return Err("unable to store password in keyring".to_owned());
            }
        }

        Ok(())
    }

    pub fn delete_password(&self) -> Result<(), String> {
        const KEYCTL_INVALIDATE: c_int = 21;

        unsafe {
            let err = Err("unable to remove key from keyring".to_owned());

            let key_id = match syscall(
                SYS_request_key,
                b"user\0", // type for user-defined keyrings
                self.desc.as_ptr(),
                ptr::null::<c_char>(),
                0,
            ) {
                -1 => {
                    info!("keyctl key decription: {:?}", self.desc);
                    info!("errno: {:?}", io::Error::last_os_error());
                    return err;
                }
                val => val,
            };

            if -1 == syscall(SYS_keyctl, KEYCTL_INVALIDATE, key_id) {
                info!("errno: {:?}", io::Error::last_os_error());
                return err;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl fmt::Display for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "description: {})", self.desc.to_string_lossy())
    }
}
