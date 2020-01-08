use log::*;

use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::{ptr, sync::atomic};

pub struct Pwd(String);

impl AsRef<str> for Pwd {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Drop for Pwd {
    fn drop(&mut self) {
        info!("zeroing password memory");
        zero_memory(&mut self.0)
    }
}

#[cfg(unix)]
pub struct Stdin(Option<libc::termios>);

#[cfg(windows)]
pub struct Stdin(winapi::shared::minwindef::DWORD);

impl Drop for Stdin {
    fn drop(&mut self) {
        self.reset_tty();
    }
}

impl Stdin {
    pub fn new() -> Self {
        new_internal().unwrap_or_else(|e| {
            warn!("platform API call error: {}", e);
            Stdin(None)
        })
    }

    pub fn is_tty(&self) -> bool {
        self.0.is_some()
    }

    pub fn read_password(&self) -> Pwd {
        let pwd = read_password(self.0).unwrap();
        self.reset_tty();
        Pwd(pwd)
    }

    pub fn reset_tty(&self) {
        info!("resetting TTY params");
        reset_internal(self.0);
    }
}

#[cfg(unix)]
fn reset_internal(termios: Option<libc::termios>) {
    use libc::{tcsetattr, STDIN_FILENO, TCSANOW};

    if let Some(termios) = termios {
        unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &termios) };
    }
}

#[cfg(windows)]
fn reset_internal(mode: Option<winapi::shared::minwindef::DWORD>) {
    use winapi::um::consoleapi::SetConsoleMode;
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;

    if let Some(mode) = mode {
        unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode) }
    }
}

#[cfg(unix)]
fn new_internal() -> ::std::io::Result<Stdin> {
    use libc::{isatty, tcgetattr, STDIN_FILENO};

    unsafe {
        let mut termios = MaybeUninit::uninit();

        if isatty(STDIN_FILENO) != 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "stdin is not a tty"));
        }

        if tcgetattr(STDIN_FILENO, termios.as_mut_ptr()) == 0 {
            return Ok(Stdin(Some(termios.assume_init())));
        }
    }

    Err(io::Error::last_os_error())
}

#[cfg(windows)]
fn new_internal() -> ::std::io::Result<Stdin> {
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };

    Ok(Stdin(None))
}

#[cfg(unix)]
fn read_password(tty: Option<libc::termios>) -> ::std::io::Result<String> {
    use libc::{tcsetattr, ECHO, ECHONL, STDIN_FILENO, TCSANOW};

    let mut password = String::new();

    if let Some(mut termios) = tty {
        info!("read_password() :: TTY");

        termios.c_lflag &= !ECHO;
        termios.c_lflag |= ECHONL;

        unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &termios) };

        io::stdin().read_line(&mut password)?;
    } else {
        info!("read_password() :: NOT A TTY");
        io::stdin().read_to_string(&mut password)?;
    }

    trim_newlines(&mut password);

    Ok(password)
}

fn trim_newlines(password: &mut String) {
    while password.ends_with(['\n', '\r'].as_ref()) {
        password.pop();
    }
}

fn zero_memory(s: &mut String) {
    let default = u8::default();

    for c in unsafe { s.as_bytes_mut() } {
        unsafe { ptr::write_volatile(c, default) };
    }

    atomic::fence(atomic::Ordering::SeqCst);
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}
