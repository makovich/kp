use atty::Stream::Stdin;
use kdbx4::Entry;
use keyring::Keyring;
use rpassword::read_password_from_tty;
use skim::{Skim, SkimOptions};

use log::*;

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

pub fn get_pwd(filename: &str, force: bool) -> Option<String> {
    if atty::isnt(Stdin) {
        use std::io::Read;
        let mut pwd = String::new();
        std::io::stdin()
            .read_to_string(&mut pwd)
            .expect("Can't read password from STDIN.");

        return Some(pwd);
    }

    let (service, username) = create_from(filename);
    let keyring = Keyring::new(&service, &username);

    if !force {
        if let Ok(pwd) = keyring.get_password() {
            debug!("using password from keyring ({})", service);
            return Some(pwd);
        }
    }

    let pwd = read_password_from_tty(Some("Password:")).unwrap();

    if keyring.set_password(&pwd).is_err() {
        warn!("unable to store the password in keyring");
    }

    Some(pwd)
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
