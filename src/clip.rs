use crate::utils;
use crate::Args;
use crate::CliResult;

use atty::Stream::Stdout;
use clipboard::{ClipboardContext, ClipboardProvider};
use ctrlc::set_handler as ctrlc_handler;
use kdbx4::{CompositeKey, Entry, Kdbx4};

use log::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time;

pub(super) fn run(args: Args) -> CliResult {
    let file = args.flag_database.unwrap();
    let key = CompositeKey::new(
        utils::get_pwd(&file, args.flag_ask_password),
        args.flag_key_file,
    )?;
    let db = Kdbx4::open(file, key)?;
    let query = args.arg_entry.as_ref().map(String::as_ref);

    if let Some(query) = query {
        if let [entry] = db.find(query).as_slice() {
            if atty::is(Stdout) {
                return clip(entry, args.flag_timeout);
            } else {
                put!("{}", entry.password()?);
                return Ok(());
            }
        }
    }

    // If more than a single match has been found and stdout is not a TTY
    // than it is not possible to pick the right entry without user's interaction
    if atty::isnt(Stdout) {
        return Err(From::from(format!(
            "No single match for {}.",
            query.unwrap_or("[empty]")
        )));
    }

    if let Some(entry) = utils::skim(&db.entries(), query, args.flag_no_group) {
        clip(entry, args.flag_timeout)?
    }

    Ok(())
}

fn clip<'a>(entry: &'a Entry<'a>, timeout: Option<u8>) -> CliResult {
    let pwd = entry.password()?;
    set_clipboard(Some(pwd));

    if timeout.is_none() {
        debug!("user decided to leave the password in the buffer");
        return Ok(());
    }

    let cancel = Arc::new(AtomicBool::new(false));

    {
        let cancel = Arc::clone(&cancel);
        ctrlc_handler(move || {
            set_clipboard(None);
            cancel.store(true, Ordering::SeqCst);
        })?;
    }

    // Check the cancellation token every one fifth of a second
    let freq = 5;
    let mut ticks = u64::from(timeout.unwrap()) * freq;

    while !cancel.load(Ordering::Relaxed) && ticks > 0 {
        if ticks % freq == 0 {
            // Note extra space after a dot
            put!("Copied! Clear in {} seconds. \x0D", ticks / freq);
        }
        thread::sleep(time::Duration::from_millis(1_000 / freq));
        ticks -= 1;
    }

    set_clipboard(None);
    wout!("{:30}", "Wiped out");

    return Ok(());
}

fn set_clipboard(val: Option<String>) {
    let ctx: Option<ClipboardContext> = ClipboardProvider::new().ok();
    if let Some(mut clip) = ctx {
        if clip.set_contents(val.unwrap_or_default()).is_err() {
            warn!("could not set the clipboard")
        }
    }
}
