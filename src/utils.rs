use crate::keyring::Keyring;
use crate::Result;
use crate::STDIN;

use clipboard::{ClipboardContext, ClipboardProvider};
use kdbx4::{CompositeKey, Database, Entry, Kdbx4};
use skim::{Skim, SkimOptions};

use log::*;

use std::io;
use std::path::Path;

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

pub fn open_database(dbfile: &Path, keyfile: Option<&Path>, use_keyring: bool) -> Result<Database> {
    let keyring = if use_keyring {
        Keyring::from_db_path(dbfile).map(|k| {
            debug!("keyring: {}", k);
            k
        })
    } else {
        None
    };

    // Try to open DB with a key from keyring
    if let Some(Ok(pwd)) = keyring.as_ref().map(|k| k.get_password()) {
        let key = CompositeKey::new(Some(&pwd), keyfile)?;
        if let Ok(db) = Kdbx4::open(dbfile, key) {
            return Ok(db);
        }

        warn!("removing wrong password in the keyring");
        let _ = keyring.as_ref().map(|k| k.delete_password());
    }

    // Try read password from pipe
    if !is_tty(io::stdin()) {
        let pwd = STDIN.read_password();
        let key = CompositeKey::new(Some(&pwd), keyfile)?;
        let db = Kdbx4::open(dbfile, key)?;
        return Ok(db);
    }

    // Allow multiple attempts to enter the password from TTY
    let mut att = 3;
    loop {
        put!("Password:");

        let pwd = STDIN.read_password();
        let key = CompositeKey::new(Some(&pwd), keyfile)?;
        let db = Kdbx4::open(dbfile, key);

        // If opened successfully store the password
        if db.is_ok() {
            let _ = keyring.as_ref().map(|k| k.set_password(&pwd));
        }

        att -= 1;

        if db.is_ok() || att == 0 {
            break db.map_err(From::from);
        }

        wout!("{} attempt(s) left.", att);
    }
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
