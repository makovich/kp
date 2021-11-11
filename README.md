# kp

![kp](https://raw.githubusercontent.com/makovich/kp/assets/kp-howto.gif "quick intro")

## Features
* macOS, Linux
* [KDBX v4](https://keepass.info/help/kb/kdbx_4.html)
* fuzzy matching prompt with [skim](https://github.com/lotabout/skim/)
* support system clipboard (macOS, X11 in Linux)
* master password store/load from [Keychain](https://en.wikipedia.org/wiki/Keychain_(software)) and [keyrings](http://man7.org/linux/man-pages/man7/keyrings.7.html)
* easy scripting (e.g. `BORG_PASSCOMMAND="kp homebackup"`)

## Install

Use [releases page](https://github.com/makovich/kp/releases) or install from crates.io with `cargo`:
```
$ cargo install kp

# or without clipboard support
$ cargo install kp --no-default-features
```

## Usage
```
$ kp --help
kp 0.1.0
    KeePass KDBX4 password reader.

Usage:
    kp [options] [<command>] [<entry>]
    kp --help

Commands:
    clip     Copy password and clear clipboard after specified amount of time.
             This is default command if no other provided.

    info     Display entry's info. Alias `show`.

Options:
    -d, --database <file>       KDBX file path.
    -k, --key-file <keyfile>    Path to the key file unlocking the database.
    -p, --use-keyring           Store password for the database in the OS's keyring.
    -P, --remove-key            Remove database's password from OS's keyring and exit.
    -G, --no-group              Show entries without group(s).
    -t, --timeout <seconds>     Timeout in seconds before clearing the clipboard.
                                Default to 15 seconds. 0 means no clean-up.
    -h, --help
    -V, --version

Environment variables:
    KP_DEFAULTS                 Set default arguments (see examples).

Examples:
    Open a database and copy password to the clipboard after selection:
      $ kp --database /root/secrets.kdbx

    Set default database, secret file and options via environment variable:
      export KP_DEFAULTS="-d$HOME/my.kdbx -k$HOME/.secret -pGt7"

    Display selector and then print entry's info:
      $ kp info

    Copy password if only single entry found otherwise display selector:
      $ kp clip gmail

    `clip` command name can be omitted:
      $ kp gmail

    Print password to STDOUT:
      $ kp github.com | cat

    Read password from STDIN:
      $ cat /mnt/usb/key | kp
```

## License

MIT/Unlicensed
