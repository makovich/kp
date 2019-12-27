use crate::utils;
use crate::Args;
use crate::CliResult;

use kdbx4::{CompositeKey, Kdbx4};

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
            wout!("-----");
            put!("{}", entry);
            wout!("-----");
            return Ok(());
        }
    }

    if let Some(entry) = utils::skim(&db.entries(), query, args.flag_no_group) {
        wout!("-----");
        put!("{}", entry);
        wout!("-----");
        return Ok(());
    }

    Ok(())
}
