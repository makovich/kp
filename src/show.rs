use crate::{utils, Args, Result};

pub(super) fn run(args: Args) -> Result<()> {
    let db = utils::open_database(
        args.flag_database,
        args.flag_key_file,
        args.flag_use_keyring,
    )?;

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
