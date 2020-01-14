use crate::pwd::Pwd;

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "macos")]
pub struct Keyring<'a> {
    keyname: &'a str,
    account: &'a str,
    keychain: SecKeychain,
}

#[cfg(target_os = "macos")]
impl<'a> Keyring<'a> {
    pub fn new(keyname: &'a str, account: &'a str) -> Result<Self, String> {
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
            .find_generic_password(self.keyname, self.account)
            .map(|(pwd, _)| unsafe { String::from_utf8_unchecked(pwd.to_owned()) })
            .map(Pwd::from)
            .map_err(|e| format!("{}", e))
    }

    pub fn set_password(&self, password: &str) -> Result<(), String> {
        self.keychain
            .set_generic_password(self.keyname, self.account, password.as_bytes())
            .map_err(|e| format!("{}", e))
    }

    pub fn delete_password(&self) -> Result<(), String> {
        self.keychain
            .find_generic_password(self.keyname, self.account)
            .map(|(_, key)| key.delete())
            .map_err(|e| format!("{}", e))
    }
}
