use crate::keyring::Keyring;
use crate::Result;
use crate::STDIN;

use clipboard::{ClipboardContext, ClipboardProvider};
use kdbx4::{CompositeKey, Database, Entry, Kdbx4};
use skim::{Skim, SkimOptions};

use log::*;

use std::io;

#[macro_export]
macro_rules! put {
    ($($arg:tt)*) => {
        use std::io::Write;
        let _ = write!(&mut ::std::io::stdout(), $($arg)*);
        let _ = ::std::io::stdout().flush();
    };
}

#[macro_export]
macro_rules! wout {
    ($($arg:tt)*) => ({
        use std::io::Write;
        let _ = writeln!(&mut ::std::io::stdout(), $($arg)*);
        let _ = ::std::io::stdout().flush();
    });
}

#[macro_export]
macro_rules! werr {
    ($($arg:tt)*) => ({
        use std::io::Write;
        let _ = writeln!(&mut ::std::io::stderr(), $($arg)*);
        let _ = ::std::io::stderr().flush();
    });
}

pub fn open_database(
    path: Option<String>,
    keyfile: Option<String>,
    use_keyring: bool,
) -> Result<Database> {
    let dbfile = path.unwrap();

    if !is_tty(io::stdin()) {
        let pwd = STDIN.read_password();
        let key = CompositeKey::new(Some(pwd), keyfile)?;
        let db = Kdbx4::open(dbfile, key)?;
        return Ok(db);
    }

    let (service, username) = create_from(&dbfile);
    let keyring = Keyring::new(&service, &username)?;

    if use_keyring {
        if let Ok(pwd) = keyring.get_password() {
            debug!("using password from keyring ({}/{})", service, username);

            let key = CompositeKey::new(Some(pwd), keyfile.as_ref())?;
            if let Ok(db) = Kdbx4::open(&dbfile, key) {
                return Ok(db);
            }

            warn!("wrong password in the keyring");
            let _ = keyring.delete_password();
        }
    }

    let mut att = 3;
    loop {
        put!("Password:");

        let pwd = STDIN.read_password();
        let key = CompositeKey::new(Some(&pwd), keyfile.as_ref())?;
        let db = Kdbx4::open(&dbfile, key);

        if db.is_ok() {
            if use_keyring && keyring.set_password(pwd.as_ref()).is_err() {
                warn!("unable to store the password in keyring");
            }
        }

        att -= 1;

        if db.is_ok() || att == 0 {
            break db.map_err(From::from);
        }

        wout!("{} attempt(s) left.", att);
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

    let result = Skim::run_with(&opts, Some(Box::new(::std::io::Cursor::new(input))))
        .map(|o| o.selected_items)
        .unwrap_or_else(Vec::new);

    if let [item] = result.as_slice() {
        Some(&entries[item.get_index()])
    } else {
        None
    }
}

pub fn set_clipboard(val: Option<String>) -> Result<()> {
    ClipboardProvider::new()
        .and_then(|mut ctx: ClipboardContext| ctx.set_contents(val.unwrap_or_default()))
        .map_err(|e| {
            warn!("could not set the clipboard: {}", e);
            e
        })
}

pub fn is_tty(fd: impl std::os::unix::io::AsRawFd) -> bool {
    unsafe { ::libc::isatty(fd.as_raw_fd()) == 1 }
}
