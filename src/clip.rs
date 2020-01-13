use crate::{utils, Args, CliResult, CANCEL, CANCEL_RQ_FREQ, STDIN};

use log::*;

use std::thread;
use std::time;

pub(super) fn run(args: Args) -> CliResult {
    let db = utils::open_database(
        args.flag_database,
        args.flag_key_file,
        args.flag_use_keyring,
    )?;

    let query = args.arg_entry.as_ref().map(String::as_ref);

    if let Some(query) = query {
        if let [entry] = db.find(query).as_slice() {
            if STDIN.is_tty() {
                return clip(entry, args.flag_timeout);
            } else {
                put!("{}", entry.password()?);
                return Ok(());
            }
        }
    }

    // If more than a single match has been found and stdout is not a TTY
    // than it is not possible to pick the right entry without user's interaction
    if !STDIN.is_tty() {
        return Err(format!("No single match for {}.", query.unwrap_or("[empty]")).into());
    }

    if let Some(entry) = utils::skim(&db.entries(), query, args.flag_no_group) {
        clip(entry, args.flag_timeout)?
    }

    Ok(())
}

fn clip<'a>(entry: &'a kdbx4::Entry<'a>, timeout: Option<u8>) -> CliResult {
    let pwd = entry.password()?;

    if utils::set_clipboard(Some(pwd)).is_err() {
        return Err("Could not copy to the clipboard. Try to use standard out, i.e. \"kp clip example.com | cat\".".into());
    }

    if timeout.is_none() {
        debug!("user decided to leave the password in the buffer");
        return Ok(());
    }

    let mut ticks = u64::from(timeout.unwrap()) * CANCEL_RQ_FREQ;
    while !CANCEL.load(std::sync::atomic::Ordering::SeqCst) && ticks > 0 {
        if ticks % CANCEL_RQ_FREQ == 0 {
            // Note extra space after the "seconds...":
            // transition from XX digits to X digit
            // would shift whole line to the left
            // so extra space's role is to hide a single dot
            put!(
                "Copied to the clipboard! Clear in {} seconds... \x0D",
                ticks / CANCEL_RQ_FREQ
            );
        }
        thread::sleep(time::Duration::from_millis(1_000 / CANCEL_RQ_FREQ));
        ticks -= 1;
    }

    let _ = utils::set_clipboard(None);
    wout!("{:50}", "Wiped out");

    return Ok(());
}
