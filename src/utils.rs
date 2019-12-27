use kdbx4::Entry;
use keyring::Keyring;
use rpassword::read_password_from_tty;
use skim::{Skim, SkimOptions};

use log::*;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Cursor;

#[macro_export]
macro_rules! put {
    ($($arg:tt)*) => {
        use std::io::Write;
        let stdout = ::std::io::stdout();
        let mut handle = stdout.lock();
        let _ = write!(&mut handle, $($arg)*);
        let _ = handle.flush();
    };
}

#[macro_export]
macro_rules! wout {
    ($($arg:tt)*) => ({
        use std::io::Write;
        (writeln!(&mut ::std::io::stdout(), $($arg)*)).unwrap();
    });
}

#[macro_export]
macro_rules! werr {
    ($($arg:tt)*) => ({
        use std::io::Write;
        (writeln!(&mut ::std::io::stderr(), $($arg)*)).unwrap();
    });
}

#[macro_export]
macro_rules! fail {
    ($e:expr) => {
        Err(::std::convert::From::from($e))
    };
}

pub fn get_pwd(filename: &str) -> Option<String> {
    let mut hasher = DefaultHasher::new();
    filename.hash(&mut hasher);
    let service = format!("{}.keepass.cli.tool", crate::BIN_NAME);
    let username = format!("{}", hasher.finish());
    let keyring = Keyring::new(&service, &username);

    if let Ok(pwd) = keyring.get_password() {
        debug!("using password from keyring ({})", service);
        return Some(pwd);
    }

    let pwd = read_password_from_tty(Some("Password:")).ok().unwrap();

    if keyring.set_password(&pwd).is_err() {
        warn!("unable to store the password in keyring");
    }

    Some(pwd)
}

pub fn skim<'a>(
    entries: &'a [Entry<'a>],
    query: Option<&'a str>,
    hide_groups: bool,
) -> Option<&'a Entry<'a>> {
    let opts = SkimOptions {
        multi: true,
        reverse: true,
        query,
        height: Some("7"),
        bind: vec![
            "ctrl-q:ignore", // toggle interactive
            "ctrl-l:ignore", // clear screen
            "ctrl-r:ignore", // rotate mode
        ],
        delimiter: if hide_groups { None } else { Some("/") },
        nth: if hide_groups { Some("-1") } else { None },

        ..SkimOptions::default()
    };

    let input = entries
        .iter()
        .map(|e| {
            if hide_groups {
                e.title().to_string()
            } else {
                format!("/{}/{}", e.group(), e.title())
            }
        })
        .collect::<Vec<String>>()
        .join("\n");

    let result = Skim::run_with(&opts, Some(Box::new(Cursor::new(input))))
        .map(|o| o.selected_items)
        .unwrap_or_else(Vec::new);

    if let [item] = result.as_slice() {
        Some(&entries[item.get_index()])
    } else {
        None
    }
}
