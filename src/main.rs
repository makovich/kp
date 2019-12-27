#[macro_use]
mod utils;
mod clip;
mod show;

use docopt::Docopt;
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde_derive::Deserialize;

use log::*;

use std::env;
use std::error;
use std::fmt;
use std::process;

const DEFAULT_TIMEOUT: u8 = 5;

static BIN_NAME: &'static str = env!("CARGO_PKG_NAME");
static ENV_VAR_NAME: &'static str = concat!(env!("CARGO_PKG_NAME"), "_DEFAULTS");
static USAGE: &'static str = "
BIN_NAME BIN_VERSION
    KeePass KDBX4 password reader.

Usage:
    BIN_NAME [options] [<command>] [<entry>]
    BIN_NAME --help

Commands:
    clip     Copy password and clear clipboard after specified amount of time.
             This is default command if no other provided.

    show     Display entry's info.

Options:
    -d, --database <file>       KDBX file path.
    -k, --key-file <keyfile>    Path to the key file unlocking the database.
    -P, --ask-password          Request password even if it already stored in the keyring.
    -G, --no-group              Show entries without group(s).
    -t, --timeout <seconds>     Timeout in seconds before clearing the clipboard.
                                Default to DEFAULT_TIMEOUT seconds. 0 means no clean-up.
    -h, --help
    -V, --version

Environment variables:
    ENV_VAR_NAME                 Set default arguments (see examples).

Examples:
    Open a database and copy password to the clipboard after selection:
      $ BIN_NAME -d/root/secrets.kdbx

    Set default database, secret file and options via environment variable:
      export ENV_VAR_NAME=\"-d$HOME/my.kdbx -k$HOME/.secret -Gt10\"

    Display selector and then print entry's info:
      $ BIN_NAME show

    Copy password if only single entry found otherwise display selector:
      $ BIN_NAME clip gmail

    `clip` command name can be omitted:
      $ BIN_NAME gmail

    Print password to STDOUT:
      $ BIN_NAME github.com | cat

    Read password from STDIN:
      $ cat /mnt/usb/key | kp
";

type CliResult = Result<(), Box<dyn error::Error>>;

fn main() {
    env_logger::init();

    let args = get_args();

    if let Err(err) = match args.arg_command {
        Command::Clip => clip::run(args),
        Command::Show => show::run(args),
        Command::Unknown(cmd) => fail!(format!(
            "Unknown command `{}`. Use `--help` to get more info.",
            cmd
        )),
    } {
        werr!("{}", err);
        process::exit(1);
    }
}

#[derive(Debug)]
enum Command {
    Clip,
    Show,
    Unknown(String),
}

#[derive(Debug, Deserialize)]
struct Args {
    arg_command: Command,
    arg_entry: Option<String>,
    flag_timeout: Option<u8>,
    flag_no_group: bool,
    flag_ask_password: bool,
    flag_database: Option<String>,
    flag_key_file: Option<String>,
    flag_help: bool,
    flag_version: bool,
}

impl Args {
    fn from_env(dopt: &Docopt) -> Args {
        let env_var = env::var(&ENV_VAR_NAME.to_uppercase()).unwrap_or_default();

        let mut argv = "BIN_NAME clip ".to_string();
        argv.push_str(env_var.as_str().trim());

        let dopt = dopt.clone();
        dopt.argv(argv.split(' '))
            .deserialize()
            .unwrap_or_else(|_| {
                werr!("Invalid arguments in {}.", &ENV_VAR_NAME.to_uppercase());
                process::exit(1);
            })
    }

    fn from_cmdline(dopt: &Docopt) -> Args {
        let dopt = dopt.clone();
        dopt.help(true)
            .options_first(true)
            .version(Some(version()))
            .deserialize()
            .unwrap_or_else(|e| e.exit())
    }
}

fn get_args() -> Args {
    let usage = USAGE
        .replace("DEFAULT_TIMEOUT", &DEFAULT_TIMEOUT.to_string())
        .replace("ENV_VAR_NAME", &ENV_VAR_NAME.to_uppercase())
        .replace("BIN_NAME", BIN_NAME)
        .replace("BIN_VERSION", &version());

    let dopt = Docopt::new(usage).unwrap_or_else(|e| e.exit());

    let env = Args::from_env(&dopt);
    debug!("env var: {:#?}", env);

    let mut cmd = Args::from_cmdline(&dopt);
    debug!("cmd line: {:#?}", cmd);

    cmd.arg_command = match cmd.arg_command {
        Command::Unknown(ref command) if command.is_empty() => Command::Clip,

        // Unknown command becomes entry title.
        // $ kp git.sr.ht
        Command::Unknown(ref entry) if cmd.arg_entry.is_none() => {
            cmd.arg_entry = Some(entry.to_string());
            Command::Clip
        }

        // Maybe misspelled command; leave it as is.
        // $ kp klip github.com
        c => c,
    };

    cmd.flag_timeout = cmd
        .flag_timeout
        .or(env.flag_timeout)
        .or(Some(DEFAULT_TIMEOUT))
        .filter(|&t| t != 0);

    cmd.flag_no_group |= env.flag_no_group;
    cmd.flag_key_file = cmd.flag_key_file.or(env.flag_key_file);
    cmd.flag_database = cmd.flag_database.or(env.flag_database).or_else(|| {
        werr!("No database file path were not found. Use `--help` to get more info.");
        process::exit(1);
    });

    debug!("merged: {:#?}", cmd);
    cmd
}

fn version() -> String {
    let (maj, min, pat) = (
        option_env!("CARGO_PKG_VERSION_MAJOR"),
        option_env!("CARGO_PKG_VERSION_MINOR"),
        option_env!("CARGO_PKG_VERSION_PATCH"),
    );
    match (maj, min, pat) {
        (Some(maj), Some(min), Some(pat)) => format!("{}.{}.{}", maj, min, pat),
        _ => "".to_owned(),
    }
}

struct CommandVisitor;

impl<'de> Visitor<'de> for CommandVisitor {
    type Value = Command;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("`clip` or `show` commands")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(match &*s.to_lowercase() {
            "clip" => Command::Clip,
            "show" => Command::Show,
            cmd => Command::Unknown(cmd.to_owned()),
        })
    }
}

impl<'de> Deserialize<'de> for Command {
    fn deserialize<D>(d: D) -> Result<Command, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_str(CommandVisitor)
    }
}
